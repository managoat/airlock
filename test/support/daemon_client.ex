defmodule Airlock.Test.DaemonClient do
  @moduledoc """
  A daemon's side of `Managoat.Runner.Connection`'s wire protocol, over a
  real WebSocket.

  `Managoat.Runner.FakeDaemon` already exercises the connection process and
  the adapter — but it *is* the connection process, spawned directly, with
  no HTTP upgrade and no socket. So it cannot say whether
  `Airlock.Box.Endpoint` upgrades a request correctly, whether it refuses
  one without a token, or whether the handler it mounts registers with the
  host.

  This connects over TCP the way the Go daemon would, and answers requests
  from a script the test supplies. It implements only what a test needs —
  `get`, `exec` and an unknown-op refusal — because the protocol's full
  vocabulary is `FakeDaemon`'s job and duplicating it here would be a
  second thing to keep in step.
  """

  use GenServer

  @doc """
  Connect a daemon for `runner_id` to the endpoint on `port`.

  Options: `:token` (required — the endpoint's), `:replies` (a map of op
  name to the `result` to answer with), `:name` (the runner's display
  name).
  """
  @spec start_link(keyword()) :: {:ok, pid()} | {:error, term()}
  def start_link(opts), do: GenServer.start_link(__MODULE__, opts)

  @doc "Every request this daemon has been sent, oldest first."
  @spec requests(pid()) :: [map()]
  def requests(pid), do: GenServer.call(pid, :requests)

  @doc "Close the socket, as a daemon going away does."
  @spec close(pid()) :: :ok
  def close(pid), do: GenServer.stop(pid)

  @impl GenServer
  def init(opts) do
    runner_id = Keyword.fetch!(opts, :runner_id)
    port = Keyword.fetch!(opts, :port)
    token = Keyword.fetch!(opts, :token)
    query = if name = Keyword.get(opts, :name), do: "?name=#{name}", else: ""

    with {:ok, conn} <- Mint.HTTP.connect(:http, "127.0.0.1", port, protocols: [:http1]),
         {:ok, conn, ref} <-
           Mint.WebSocket.upgrade(:ws, conn, "/runner/#{runner_id}#{query}", [
             {"authorization", "Bearer #{token}"}
           ]),
         {:ok, conn, websocket} <- await_upgrade(conn, ref) do
      {:ok,
       %{
         conn: conn,
         websocket: websocket,
         ref: ref,
         replies: Keyword.get(opts, :replies, %{}),
         requests: []
       }}
    else
      {:error, reason} -> {:stop, reason}
      {:error, _conn, reason} -> {:stop, reason}
    end
  end

  @impl GenServer
  def handle_call(:requests, _from, state), do: {:reply, Enum.reverse(state.requests), state}

  @impl GenServer
  def handle_info(message, state) do
    case Mint.WebSocket.stream(state.conn, message) do
      {:ok, conn, responses} ->
        state = %{state | conn: conn}
        {:noreply, Enum.reduce(responses, state, &handle_response/2)}

      {:error, conn, _reason, _responses} ->
        {:noreply, %{state | conn: conn}}

      :unknown ->
        {:noreply, state}
    end
  end

  defp handle_response({:data, _ref, data}, state) do
    {:ok, websocket, frames} = Mint.WebSocket.decode(state.websocket, data)
    Enum.reduce(frames, %{state | websocket: websocket}, &handle_frame/2)
  end

  defp handle_response(_other, state), do: state

  defp handle_frame({:text, text}, state) do
    request = Jason.decode!(text)
    state = %{state | requests: [request | state.requests]}
    reply(state, request)
  end

  defp handle_frame({:ping, payload}, state), do: send_frame(state, {:pong, payload})
  defp handle_frame(_other, state), do: state

  defp reply(state, %{"id" => id, "op" => op}) do
    case Map.fetch(state.replies, op) do
      {:ok, result} ->
        send_frame(state, {:text, Jason.encode!(%{"id" => id, "ok" => true, "result" => result})})

      :error ->
        send_frame(
          state,
          {:text,
           Jason.encode!(%{
             "id" => id,
             "ok" => false,
             "error" => "invalid",
             "detail" => "this test daemon has no reply scripted for #{op}"
           })}
        )
    end
  end

  defp reply(state, _request), do: state

  defp send_frame(state, frame) do
    {:ok, websocket, data} = Mint.WebSocket.encode(state.websocket, frame)
    {:ok, conn} = Mint.WebSocket.stream_request_body(state.conn, state.ref, data)
    %{state | conn: conn, websocket: websocket}
  end

  defp await_upgrade(conn, ref, timeout \\ 2_000) do
    receive do
      message ->
        case Mint.WebSocket.stream(conn, message) do
          {:ok, conn, responses} ->
            case upgrade_response(responses, ref) do
              {:ok, status, headers} ->
                Mint.WebSocket.new(conn, ref, status, headers)

              :pending ->
                await_upgrade(conn, ref, timeout)
            end

          other ->
            other
        end
    after
      timeout -> {:error, :upgrade_timeout}
    end
  end

  defp upgrade_response(responses, ref) do
    status =
      Enum.find_value(responses, fn
        {:status, ^ref, status} -> status
        _ -> nil
      end)

    headers =
      Enum.find_value(responses, fn
        {:headers, ^ref, headers} -> headers
        _ -> nil
      end)

    if status && headers, do: {:ok, status, headers}, else: :pending
  end
end
