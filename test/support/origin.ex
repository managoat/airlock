defmodule Airlock.Test.Origin do
  @moduledoc """
  A test origin: an HTTP server that answers every request by echoing back
  what it received.

  The point of a broker test is what the *origin* saw — whether the real
  credential arrived where the placeholder was, and whether the box's own
  value ever left. Asserting on the proxy's own output would only test that
  the proxy agrees with itself.
  """

  import Plug.Conn

  @behaviour Plug

  @impl Plug
  def init(opts), do: opts

  @impl Plug
  def call(conn, _opts) do
    body =
      Jason.encode!(%{
        "method" => conn.method,
        "path" => conn.request_path,
        "query" => conn.query_string,
        "headers" => Map.new(conn.req_headers)
      })

    conn
    |> put_resp_content_type("application/json")
    |> send_resp(200, body)
  end

  @doc "Start an origin on an ephemeral loopback port. Returns `{pid, port}`."
  @spec start!() :: {pid(), :inet.port_number()}
  def start! do
    {:ok, pid} =
      Bandit.start_link(
        plug: __MODULE__,
        scheme: :http,
        ip: {127, 0, 0, 1},
        port: 0,
        startup_log: false
      )

    {:ok, {_ip, port}} = ThousandIsland.listener_info(pid)
    {pid, port}
  end
end
