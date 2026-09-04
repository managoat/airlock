defmodule Airlock.Test.ProxyClient do
  @moduledoc """
  An HTTP client that speaks to the broker the way a box does: absolute-form
  requests over a plain socket, with `Proxy-Authorization` on each.

  Written by hand rather than driven through an HTTP library, because the
  thing under test is the wire — which header the origin receives, and what
  the proxy does with a request it refuses — and a client that helpfully
  normalises headers or retries would hide exactly that.

  Absolute form (plain `http://`) rather than `CONNECT`, because it needs
  no TLS and therefore no trusting of the broker's CA. `CONNECT` is the
  path a real box takes for HTTPS and it is not exercised here; see
  `NOTES-M0.md`.
  """

  alias Airlock.Broker

  @doc """
  Send one request through `broker` and return
  `{:ok, status, headers, body}`.

  `headers` are the request's own, so a test can send the placeholder a box
  would have been given.
  """
  @spec request(Broker.t(), String.t(), String.t(), [{String.t(), String.t()}]) ::
          {:ok, non_neg_integer(), [{String.t(), String.t()}], binary()} | {:error, term()}
  def request(%Broker{} = broker, method, url, headers \\ []) do
    uri = URI.parse(url)
    authority = "#{uri.host}#{if uri.port, do: ":#{uri.port}", else: ""}"

    lines =
      [
        "#{method} #{url} HTTP/1.1",
        "Host: #{authority}",
        "Proxy-Authorization: Basic #{proxy_auth(broker)}",
        "Connection: close"
      ] ++ Enum.map(headers, fn {key, value} -> "#{key}: #{value}" end)

    payload = Enum.join(lines, "\r\n") <> "\r\n\r\n"

    with {:ok, socket} <-
           :gen_tcp.connect(to_charlist(broker.host), broker.port, [
             :binary,
             active: false,
             packet: :raw
           ]),
         :ok <- :gen_tcp.send(socket, payload) do
      response = read_all(socket, "")
      :gen_tcp.close(socket)
      parse(response)
    end
  end

  defp proxy_auth(%Broker{token: token, label: label}),
    do: Base.encode64("#{token}:#{label}")

  defp read_all(socket, acc) do
    case :gen_tcp.recv(socket, 0, 5_000) do
      {:ok, data} -> read_all(socket, acc <> data)
      {:error, :closed} -> acc
      {:error, _reason} -> acc
    end
  end

  defp parse(""), do: {:error, :no_response}

  defp parse(response) do
    [head, body] =
      case String.split(response, "\r\n\r\n", parts: 2) do
        [head, body] -> [head, body]
        [head] -> [head, ""]
      end

    [status_line | header_lines] = String.split(head, "\r\n")
    [_version, status | _reason] = String.split(status_line, " ")

    headers =
      for line <- header_lines, [key, value] <- [String.split(line, ": ", parts: 2)] do
        {String.downcase(key), value}
      end

    {:ok, String.to_integer(status), headers, dechunk(body, headers)}
  end

  # The origin answers with a content-length, but a proxied response may be
  # chunked; a test asserting on JSON should not have to care which.
  defp dechunk(body, headers) do
    if List.keyfind(headers, "transfer-encoding", 0) == {"transfer-encoding", "chunked"} do
      body |> String.split("\r\n") |> Enum.take_every(2) |> Enum.drop(1) |> Enum.join()
    else
      body
    end
  end
end
