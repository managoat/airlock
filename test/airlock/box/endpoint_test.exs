defmodule Airlock.Box.EndpointTest do
  @moduledoc """
  M0 step 1: "brings up a `Runner.Host` so `managoat_runner` can present a
  local box".

  What is verified here is the host and the transport: a daemon dials in
  over a real socket, the endpoint upgrades it, the connection registers
  with `Managoat.Runner.Host.Local`, and a `Managoat.Sandbox` call routes
  through the name and comes back with the daemon's answer.

  What is **not** verified is a box. `Airlock.Test.DaemonClient` answers
  from a script; nothing here creates a directory or runs a command,
  because the daemon that would is a Go binary in Fountain's private CLI
  and is not one of the nine libraries. `NOTES-M0.md` has the consequence.
  """

  use ExUnit.Case, async: false

  alias Airlock.Box.Endpoint
  alias Airlock.Box.Host
  alias Airlock.Test.DaemonClient
  alias Managoat.Runner.Adapter
  alias Managoat.Runner.Names
  alias Managoat.Sandbox
  alias Managoat.Sandbox.NetworkPolicy

  setup do
    # `Host.Local` is a named Registry and `managoat_runner`'s host is one
    # global setting, so these cannot run async. Started once per test and
    # torn down, so a test never sees another's registrations.
    start_supervised!(Host)
    Host.configure()

    token = Endpoint.generate_token()
    pid = start_supervised!({Endpoint, token: token})

    %{token: token, port: Endpoint.port(pid), runner_id: runner_id()}
  end

  describe "the door" do
    test "the guess the brief flagged is already the library's own answer" do
      # CLAUDE.md: "`Host.Local` over a plain `Registry` is the guess; it is
      # M0's first task and the guess is unverified." Measured: the library
      # ships it, so Airlock configures it rather than writing one.
      assert Host.module() == Managoat.Runner.Host.Local
    end

    test "refuses a connection with no token", %{port: port, runner_id: runner_id} do
      assert {401, _body} = get(port, "/runner/#{runner_id}", [])
    end

    test "refuses a connection with the wrong token", %{port: port, runner_id: runner_id} do
      assert {403, _body} =
               get(port, "/runner/#{runner_id}", [{"authorization", "Bearer ar_not-the-token"}])
    end

    test "refuses a runner id that is not one", %{port: port, token: token} do
      assert {400, _body} =
               get(port, "/runner/not-a-uuid", [{"authorization", "Bearer #{token}"}])
    end

    test "a refused connection never registers", %{port: port, runner_id: runner_id} do
      get(port, "/runner/#{runner_id}", [])
      assert Host.whereis(runner_id) == nil
      assert Host.online() == []
    end

    test "404s anything that is not the runner route", %{port: port} do
      assert {404, _body} = get(port, "/", [])
    end
  end

  describe "a daemon that dials in" do
    setup context do
      {:ok, daemon} =
        DaemonClient.start_link(
          runner_id: context.runner_id,
          port: context.port,
          token: context.token,
          name: "test-box",
          replies: %{"get" => %{"status" => "running"}}
        )

      on_exit(fn -> if Process.alive?(daemon), do: DaemonClient.close(daemon) end)
      wait_until(fn -> Host.whereis(context.runner_id) != nil end)
      %{daemon: daemon}
    end

    test "registers with the host under its runner id", %{runner_id: runner_id} do
      assert is_pid(Host.whereis(runner_id))
      assert [{^runner_id, meta}] = Host.online()
      assert %{connected_at: %DateTime{}} = meta
    end

    test "a Sandbox call routes through the name to the daemon and back", %{
      runner_id: runner_id,
      daemon: daemon
    } do
      # The whole path: Sandbox -> Runner.Adapter -> Names -> the host's
      # registry -> Connection -> the socket the endpoint upgraded -> the
      # daemon, and the reply back down it.
      handle = Sandbox.build_handle(:runner, Names.for_runner(runner_id))

      assert {:ok, %{status: :running}} = Sandbox.get(handle)
      assert [%{"op" => "get"}] = DaemonClient.requests(daemon)
    end

    test "an op the daemon refuses comes back in the sandbox taxonomy", %{runner_id: runner_id} do
      handle = Sandbox.build_handle(:runner, Names.for_runner(runner_id))

      # The test daemon scripts no reply for `destroy`, so it refuses with
      # `invalid` — which the adapter normalises rather than passing the
      # daemon's own string up.
      assert {:error, {:invalid, _detail}} = Sandbox.destroy(handle)
    end

    test "a name for a runner nobody connected is unavailable, never not_found" do
      # `{:unavailable, _}` is transient in the taxonomy, so a parked
      # directory on a switched-off machine is never mistaken for a sandbox
      # that is gone.
      handle = Sandbox.build_handle(:runner, Names.for_runner(runner_id()))
      assert {:error, {:unavailable, :runner_offline}} = Sandbox.get(handle)
    end

    test "the registration goes away with the socket", %{runner_id: runner_id, daemon: daemon} do
      DaemonClient.close(daemon)
      wait_until(fn -> Host.whereis(runner_id) == nil end)
      assert Host.online() == []
    end
  end

  describe "what the runner cannot do" do
    setup context do
      {:ok, daemon} =
        DaemonClient.start_link(
          runner_id: context.runner_id,
          port: context.port,
          token: context.token,
          replies: %{"get" => %{"status" => "running"}}
        )

      on_exit(fn -> if Process.alive?(daemon), do: DaemonClient.close(daemon) end)
      wait_until(fn -> Host.whereis(context.runner_id) != nil end)
      :ok
    end

    test "it refuses to be sealed, which is M0 step 6", %{runner_id: runner_id} do
      # The finding that reorders M0. `Managoat.Runner.Adapter`: ":network_policy
      # is **not** [advertised] — the machine is the user's and so is its
      # network; apply_network_policy/2 refuses rather than pretending."
      #
      # So the box M0 chose *because* the broker had to be reachable from it
      # is the one box that cannot have a network policy applied. Sprites,
      # E2B and Daytona all advertise `:network_policy`; the runner is the
      # only adapter that does not. NOTES-M0.md has the options.
      handle = Sandbox.build_handle(:runner, Names.for_runner(runner_id))

      refute :network_policy in Adapter.capabilities()

      assert {:error, :not_supported} =
               Sandbox.apply_network_policy(handle, %NetworkPolicy{allow: ["127.0.0.1:14322"]})
    end

    test "every other provider can be sealed" do
      for adapter <- [Managoat.Sandbox.Sprites, Managoat.Sandbox.E2B, Managoat.Sandbox.Daytona] do
        assert :network_policy in adapter.capabilities(),
               "#{inspect(adapter)} no longer advertises :network_policy"
      end
    end
  end

  # ── helpers ────────────────────────────────────────────────────────────────

  # A dashed UUID, which is the shape `Managoat.Runner.Names.parse/1`
  # returns and therefore the shape a registration has to be under.
  defp runner_id do
    <<a::binary-8, b::binary-4, c::binary-4, d::binary-4, e::binary-12>> =
      16 |> :crypto.strong_rand_bytes() |> Base.encode16(case: :lower)

    "#{a}-#{b}-#{c}-#{d}-#{e}"
  end

  # A plain HTTP GET, so the refusal paths are tested as a daemon would
  # meet them rather than through a WebSocket client that would give up
  # before showing the status.
  defp get(port, path, headers) do
    lines =
      ["GET #{path} HTTP/1.1", "Host: 127.0.0.1:#{port}", "Connection: close"] ++
        Enum.map(headers, fn {key, value} -> "#{key}: #{value}" end)

    {:ok, socket} =
      :gen_tcp.connect(~c"127.0.0.1", port, [:binary, active: false, packet: :raw])

    :ok = :gen_tcp.send(socket, Enum.join(lines, "\r\n") <> "\r\n\r\n")
    response = read_all(socket, "")
    :gen_tcp.close(socket)

    [status_line | _rest] = String.split(response, "\r\n")
    [_version, status | _reason] = String.split(status_line, " ")
    {String.to_integer(status), response}
  end

  defp read_all(socket, acc) do
    case :gen_tcp.recv(socket, 0, 2_000) do
      {:ok, data} -> read_all(socket, acc <> data)
      {:error, _reason} -> acc
    end
  end

  defp wait_until(predicate, attempts \\ 100) do
    cond do
      predicate.() -> :ok
      attempts > 0 -> Process.sleep(10) && wait_until(predicate, attempts - 1)
      true -> flunk("condition never became true")
    end
  end
end
