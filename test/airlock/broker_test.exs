defmodule Airlock.BrokerTest do
  @moduledoc """
  M0's "done when", minus the agent.

  > the egress log shows at least one `injected` row, one `passthrough` row
  > and one `denied` row, each naming the rule that decided it

  There is no box here and no agent — steps 4 through 7 are not built. What
  is here is the other half of that sentence: a client that behaves the way
  a box does, a real proxy, and a real origin that says what it received.
  Whether the box ever holds the credential is `Airlock.Policy`'s question
  and is tested there; whether the credential arrives at the origin having
  never left the proxy is this one's.
  """

  use ExUnit.Case, async: true

  alias Airlock.Broker
  alias Airlock.Egress
  alias Airlock.Policy
  alias Airlock.Test.Origin
  alias Airlock.Test.ProxyClient
  alias Managoat.Broker.Session

  @stripe_key "sk_test_51_not_a_real_key"
  @anthropic_key "sk-ant-api03-not-a-real-key"

  setup context do
    {origin, port} = Origin.start!()
    on_exit(fn -> if Process.alive?(origin), do: Process.exit(origin, :normal) end)

    policy = policy(port)

    {:ok, broker} =
      Broker.start_link(
        policy: policy,
        vars: %{"STRIPE_KEY" => @stripe_key, "ANTHROPIC_API_KEY" => @anthropic_key},
        name: Module.concat(__MODULE__, "L#{:erlang.phash2(context.test)}"),
        # The origin is on loopback, which is what this option is for and
        # the only reason it is ever true. `Airlock.Policy.Compile` says
        # why the local *box* does not need it: the box-to-proxy connection
        # is not an upstream, so a real local run leaves it false.
        allow_private_upstreams: true
      )

    {:ok, _egress} = Egress.start_link(run: broker.run)
    on_exit(fn -> Egress.detach(broker.run) end)

    %{broker: broker, policy: policy, origin_port: port}
  end

  describe "the session a run is served under" do
    test "denies a host no rule names", %{broker: broker} do
      assert {:ok, %Session{unmatched_host_policy: :deny}} = Broker.session(broker)
    end

    test "expires when the policy says", %{broker: broker} do
      assert {:ok, %Session{expires_at: %DateTime{} = at}} = Broker.session(broker)
      assert DateTime.diff(at, DateTime.utc_now()) in 3500..3600
    end

    test "carries the run in meta, which is what keeps a global handler honest", %{broker: broker} do
      assert {:ok, %Session{meta: %{run: run}}} = Broker.session(broker)
      assert run == broker.run
    end

    test "holds every placeholder, not the one provisioning chose", %{broker: broker} do
      assert broker.placeholders == %{"ANTHROPIC_API_KEY" => "PLACEHOLDER-ANTHROPIC"}
    end
  end

  describe "what the box is told" do
    test "a proxy URL with the token, and NO_PROXY for loopback", %{broker: broker} do
      env = Broker.box_env(broker)

      assert env["HTTPS_PROXY"] == Broker.proxy_url(broker)
      assert env["https_proxy"] == env["HTTPS_PROXY"]
      assert env["NO_PROXY"] =~ "127.0.0.1"
      assert env["HTTPS_PROXY"] =~ broker.token
    end

    test "placeholders where the credentials would be, and never a credential", %{broker: broker} do
      env = Broker.box_env(broker)

      assert env["ANTHROPIC_API_KEY"] == "PLACEHOLDER-ANTHROPIC"
      refute inspect(env) =~ @anthropic_key
      refute inspect(env) =~ @stripe_key
    end

    test "a CA the box must trust, derived from this run's seed", %{broker: broker} do
      assert Broker.ca_pem(broker) =~ "BEGIN CERTIFICATE"
    end
  end

  describe "the egress log" do
    test "an injected row: the credential is attached at the proxy", ctx do
      %{broker: broker, origin_port: port} = ctx

      assert {:ok, 200, _headers, body} =
               ProxyClient.request(broker, "GET", "http://127.0.0.1:#{port}/v1/customers")

      # The origin saw the real key. The client never sent one.
      assert %{"headers" => headers} = Jason.decode!(body)
      assert headers["authorization"] == "Bearer #{@stripe_key}"

      assert %{verdict: :injected, rule: "stripe", status: 200, host: "127.0.0.1"} =
               await_row(broker.run, "127.0.0.1")
    end

    test "a passthrough row: an allowed host on a path no credential covers", ctx do
      %{broker: broker, origin_port: port} = ctx

      assert {:ok, 200, _headers, body} =
               ProxyClient.request(broker, "GET", "http://127.0.0.1:#{port}/index")

      # Nothing was attached: the host is reachable because `allow` says
      # so, and the rule that says so names itself in the log.
      assert %{"headers" => headers} = Jason.decode!(body)
      refute Map.has_key?(headers, "authorization")

      # The event itself says `:injected` here — a rule matched, so it does.
      # The verdict comes from that rule's `scheme`, which is the only way a
      # reader learns nothing was attached. managoat_broker#27, filed from
      # this module and closed in 0.11.0 by adding the field; this is it
      # working against a real proxy rather than a hand-fed event.
      assert %{verdict: :passthrough, rule: "allow:127.0.0.1", status: 200} =
               await_row(broker.run, "127.0.0.1")
    end

    test "a denied row: a host the policy does not name", %{broker: broker} do
      assert {:ok, 403, _headers, _body} =
               ProxyClient.request(broker, "GET", "http://pastebin.example/raw/x9f2")

      # Refused at the proxy before anything was dialled, so this row costs
      # no DNS and no network — which is why it is a row and not a timeout.
      assert %{verdict: :denied, status: 403, rule: nil, path: "/raw/x9f2"} =
               await_row(broker.run, "pastebin.example")
    end

    test "all three rows, which is what M0 asks for", ctx do
      %{broker: broker, origin_port: port} = ctx

      ProxyClient.request(broker, "GET", "http://127.0.0.1:#{port}/v1/customers")
      ProxyClient.request(broker, "GET", "http://localhost:#{port}/index")
      ProxyClient.request(broker, "GET", "http://pastebin.example/raw/x9f2")

      rows = await_rows(broker.run, 3)

      assert rows |> Enum.map(& &1.verdict) |> Enum.sort() == [:denied, :injected, :passthrough]
      assert Enum.all?(rows, &(&1.method == "GET"))
      # Every row that decided something names the rule that decided it.
      assert Enum.find(rows, &(&1.verdict == :injected)).rule == "stripe"
      assert Enum.find(rows, &(&1.verdict == :passthrough)).rule == "allow:localhost"
    end

    test "the query string never reaches a row", ctx do
      %{broker: broker, origin_port: port} = ctx

      ProxyClient.request(
        broker,
        "GET",
        "http://127.0.0.1:#{port}/v1/customers?key=#{@stripe_key}"
      )

      row = await_row(broker.run, "127.0.0.1")

      # The library drops it: a query can carry a credential the proxy
      # never saw and therefore never brokered.
      assert row.path == "/v1/customers"
      refute inspect(row) =~ @stripe_key
    end
  end

  describe "substitution" do
    test "the placeholder the box holds is worth nothing until the proxy sees it", ctx do
      %{broker: broker, origin_port: port} = ctx

      # Exactly what a runtime does: it was handed a placeholder as its API
      # key and it sends it, believing it is a credential.
      assert {:ok, 200, _headers, body} =
               ProxyClient.request(broker, "GET", "http://localhost:#{port}/v1/messages", [
                 {"x-api-key", "PLACEHOLDER-ANTHROPIC"}
               ])

      assert %{"headers" => headers} = Jason.decode!(body)
      assert headers["x-api-key"] == @anthropic_key
    end

    test "a substituted request is an injected row, and names the rule", ctx do
      %{broker: broker, origin_port: port} = ctx

      ProxyClient.request(broker, "GET", "http://localhost:#{port}/v1/messages", [
        {"x-api-key", "PLACEHOLDER-ANTHROPIC"}
      ])

      # A real credential reached the origin, so the record has to say a
      # credential was attached. The event alone could not: `:substitute`
      # sets no header, and the outcome would be `:injected` here whether
      # or not it had. The rule's scheme is what makes it true rather than
      # accidentally right.
      row = await_row(broker.run, "localhost")
      assert row.verdict == :injected
      assert row.rule == "anthropic"
    end
  end

  describe "a run that cannot start" do
    test "names every missing variable rather than the first" do
      assert {:error, {:missing_vars, ["ANTHROPIC_API_KEY", "STRIPE_KEY"]}} =
               Broker.start_link(policy: policy(1234), vars: %{}, name: MissingVars)
    end
  end

  # ── helpers ────────────────────────────────────────────────────────────────

  # One origin, reached under two names and three paths, which is what
  # gives every verdict a row without needing three servers:
  #
  #   127.0.0.1/v1/customers  bearer      -> injected
  #   127.0.0.1/anything-else allow only  -> passthrough
  #   localhost/v1/messages   substitute  -> injected, credential swapped in
  #   pastebin.example        no rule     -> denied
  #
  # The bearer rule is scoped to a path deliberately: it is the case the
  # compiler's passthrough rules exist for, and it is what makes a
  # passthrough row reachable under `unmatched: deny` at all.
  defp policy(port) do
    {:ok, policy} =
      Policy.parse("""
      allow:
        - 127.0.0.1
        - localhost

      credentials:
        - host: "127.0.0.1:#{port}/v1/customers"
          name: stripe
          scheme: bearer
          from: env:STRIPE_KEY

        - host: "localhost:#{port}/v1/messages"
          name: anthropic
          scheme: substitute
          placeholder: "PLACEHOLDER-ANTHROPIC"
          from: env:ANTHROPIC_API_KEY

      unmatched: deny
      expires_in: "1h"
      """)

    policy
  end

  # The request event is terminal: it fires when the request *ends*, so a
  # row is not there the moment the client has its response.
  defp await_row(run, host, attempts \\ 100) do
    case Enum.find(Egress.rows(run), &(&1.host == host)) do
      nil when attempts > 0 ->
        Process.sleep(10)
        await_row(run, host, attempts - 1)

      nil ->
        flunk("no egress row for #{host} after a second; rows: #{inspect(Egress.rows(run))}")

      row ->
        row
    end
  end

  defp await_rows(run, count, attempts \\ 100) do
    rows = Egress.rows(run)

    cond do
      length(rows) >= count -> rows
      attempts > 0 -> Process.sleep(10) && await_rows(run, count, attempts - 1)
      true -> flunk("only #{length(rows)} rows after a second: #{inspect(rows)}")
    end
  end
end
