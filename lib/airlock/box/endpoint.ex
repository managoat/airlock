defmodule Airlock.Box.Endpoint do
  @moduledoc """
  The WebSocket endpoint a runner daemon dials into.

  `managoat_runner` depends on `websock` — the behaviour only — and says
  the adapter that mounts a handler on a Plug connection "belongs to the
  host application". This is that: Bandit, one route, and
  `WebSockAdapter.upgrade/4` handing `Managoat.Runner.Connection` the init
  map its moduledoc specifies.

      GET /runner/<runner_id>?name=<display name>
      Authorization: Bearer <token>

  The daemon's side of the protocol is `Managoat.Runner.Connection`'s
  moduledoc; nothing about it is here, because nothing about it is the
  endpoint's business. The endpoint authenticates a connection, names it,
  and gets out of the way.

  ## The token is not optional

  This endpoint grants a caller the ability to run commands on the machine
  it is listening on. It binds to loopback by default and it still requires
  a bearer token, because loopback is not a boundary on a shared machine —
  any local process, and any page a browser can be talked into fetching,
  reaches `127.0.0.1`. The token is minted per Airlock process and is
  compared with `Plug.Crypto.secure_compare/2`.

  A connection with no token, a wrong token, or an unparseable runner id is
  refused before the upgrade, so it never reaches
  `Managoat.Runner.Connection` and never registers with the host.

  ## Not yet exercised by a real daemon

  Verified against a WebSocket client speaking the protocol by hand
  (`test/airlock/box/endpoint_test.exs`): the upgrade, the token check, the
  registration with `Airlock.Box.Host`, and one request/reply round trip
  through `Managoat.Sandbox`. **No real daemon has connected to it**, for
  the reason `Airlock.Box.Host` records: the daemon is Go, it lives in
  Fountain's private CLI, and it is not one of the nine libraries.
  """

  use Plug.Router

  alias Managoat.Runner.Connection
  alias Managoat.Runner.Names

  require Logger

  plug(:match)
  plug(:dispatch)

  # `use Plug.Router` builds `call/2` and consumes the opts, so the token
  # the endpoint was started with has to be stashed where a route can read
  # it. This is the documented way to reach `init/1`'s opts from a route.
  @impl Plug
  def call(conn, opts) do
    conn |> put_private(:airlock_token, Keyword.fetch!(opts, :token)) |> super(opts)
  end

  @doc """
  Start the endpoint.

  Options: `:token` (required), `:port` (default `0`, an ephemeral one),
  `:ip` (default `{127, 0, 0, 1}` — loopback, because the daemon is on this
  machine and `Airlock` is not a service).
  """
  @spec start_link(keyword()) :: {:ok, pid()} | {:error, term()}
  def start_link(opts) do
    token = Keyword.fetch!(opts, :token)

    Bandit.start_link(
      plug: {__MODULE__, token: token},
      scheme: :http,
      ip: Keyword.get(opts, :ip, {127, 0, 0, 1}),
      port: Keyword.get(opts, :port, 0),
      startup_log: false
    )
  end

  @doc "A child spec, so the endpoint can sit in a supervision tree."
  @spec child_spec(keyword()) :: Supervisor.child_spec()
  def child_spec(opts) do
    %{id: __MODULE__, start: {__MODULE__, :start_link, [opts]}, type: :supervisor}
  end

  @doc "The port the endpoint bound to."
  @spec port(pid()) :: :inet.port_number()
  def port(pid) when is_pid(pid) do
    {:ok, {_ip, port}} = ThousandIsland.listener_info(pid)
    port
  end

  @doc "Mint a token for the endpoint. 32 random bytes, url-safe."
  @spec generate_token() :: String.t()
  def generate_token,
    do: "ar_" <> Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false)

  @doc "The URL a daemon dials for `runner_id`."
  @spec url(:inet.port_number(), String.t()) :: String.t()
  def url(port, runner_id), do: "ws://127.0.0.1:#{port}/runner/#{runner_id}"

  # ── routes ─────────────────────────────────────────────────────────────────

  get "/runner/:runner_id" do
    with :ok <- authenticate(conn), {:ok, runner_id} <- canonical_runner_id(runner_id) do
      init = %{
        runner_id: runner_id,
        name: display_name(conn, runner_id),
        meta: %{connected_at: DateTime.utc_now()}
      }

      WebSockAdapter.upgrade(conn, Connection, init, timeout: :infinity)
    else
      {:error, status, reason} ->
        # Never the token, and never how close a wrong one was.
        Logger.warning("airlock: refused a runner connection: #{reason}")
        send_resp(conn, status, reason)
    end
  end

  match _ do
    send_resp(conn, 404, "not found")
  end

  # ── the door ───────────────────────────────────────────────────────────────

  defp authenticate(conn) do
    expected = conn.private[:airlock_token]

    case get_req_header(conn, "authorization") do
      ["Bearer " <> given] -> compare(given, expected)
      _ -> {:error, 401, "a bearer token is required"}
    end
  end

  defp compare(given, expected) when is_binary(expected) do
    if byte_size(given) == byte_size(expected) and Plug.Crypto.secure_compare(given, expected) do
      :ok
    else
      {:error, 403, "that token is not this endpoint's"}
    end
  end

  defp compare(_given, _expected), do: {:error, 500, "this endpoint has no token"}

  # A runner id is a UUID and it registers in **one** shape: the lowercase
  # dashed form `Managoat.Runner.Names.parse/1` returns.
  #
  # This matters more than it looks. The adapter is handed nothing but a
  # sandbox name; it parses the runner id back out of it and looks that up
  # with `whereis/1`. If a daemon dialled in with an undashed or uppercase
  # id, it would register under a key nothing ever looks up, and every call
  # would come back `{:unavailable, :runner_offline}` — a transient error
  # in the taxonomy, so a caller would retry a runner that is connected and
  # will never answer. Canonicalising here is what keeps the two halves
  # agreeing about the same runner.
  defp canonical_runner_id(runner_id) do
    hex = runner_id |> String.replace("-", "") |> String.downcase()

    case Names.parse("runner-" <> hex <> "-00000000") do
      {:ok, canonical} -> {:ok, canonical}
      :error -> {:error, 400, "that is not a runner id"}
    end
  end

  defp display_name(conn, runner_id) do
    conn = fetch_query_params(conn)
    conn.query_params["name"] || runner_id
  end
end
