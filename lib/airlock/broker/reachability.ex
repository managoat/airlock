defmodule Airlock.Broker.Reachability do
  @moduledoc """
  The address **the box** reaches the broker by, and the check that it is
  one the box could possibly reach.

  `CLAUDE.md` calls this the constraint that shapes the architecture: the
  broker is a listener the sandbox dials out to, so the sandbox has to be
  able to reach it. With the box on your own machine that is free. With the
  box on Sprites it is the whole deployment story.

  ## Why this is a hard error and not a warning

  Under `Airlock.Policy.Compile`'s answer the box's egress policy names the
  broker and *nothing else*. Point a Sprites box at `127.0.0.1` and the
  seal is applied, the agent comes up, and every request it makes fails to
  connect — to a loopback address inside its own sandbox. The record shows
  no rows, which is indistinguishable from an agent that made no requests,
  which is the exact failure mode `Airlock.Egress`'s moduledoc is written
  around.

  Worse, it fails *late*: after provisioning, after npm, after the seal.
  So `check/2` runs before the box is created.

  ## The token goes over the wire in the clear

  This is a finding, not a feature, and it is why `check/2` returns a
  warning alongside its verdict.

  A box talks to the broker with `Proxy-Authorization: Basic
  base64(token:label)` on every request, over a **plaintext** listener —
  `Managoat.Broker`'s `port` option is documented as "the plaintext
  listener port", and there is no TLS option on it. On a local box that is
  a loopback socket and it does not matter. Over a tunnel to a cloud
  sandbox it is the public internet, and anyone on path sees:

    * the session token, which is the authority to use every credential the
      policy names — the proxy attaches them to anything bearing it;
    * the `CONNECT` target of every request, so the host list leaks even
      though the bodies do not (they are TLS inside the tunnel).

  The token is not a credential *for* anything except this broker, and the
  session expires — `expires_in` in the policy — so the blast radius is one
  run. That is a mitigation, not a fix.

  What actually fixes it is a transport that is encrypted end to end:

  | | |
  |---|---|
  | **A tailnet** (Tailscale) | Encrypted between the two peers, no third party holds plaintext. The right answer, and it needs Tailscale on the box. |
  | **A deployed broker behind TLS** | M3's real answer. Needs the listener to speak TLS, which `Managoat.Broker` does not yet offer. |
  | **`ngrok tcp`** | Raw TCP passthrough, so the proxy protocol survives — but plaintext on the wire and ngrok sees it. Fine for a smoke test with a throwaway key. **Not fine for a real credential.** |
  | **`cloudflared` quick tunnel** | Does not work at all: it is an HTTP reverse proxy and will not forward `CONNECT`. |

  So `classify/1` names what it sees and `Airlock.Run` prints the warning
  rather than swallowing it.
  """

  @typedoc "What kind of address the box was given."
  @type kind :: :loopback | :private | :public

  @doc """
  Is `broker_host` an address a box on `provider` could reach?

  `broker_host` is `host` or `host:port` — whatever goes into the box's
  proxy environment and its egress allow list.
  """
  @spec check(String.t(), atom()) :: :ok | {:error, term()}
  def check(broker_host, provider) when is_binary(broker_host) and is_atom(provider) do
    case {classify(broker_host), local_provider?(provider)} do
      {_kind, true} ->
        :ok

      {:public, false} ->
        :ok

      {kind, false} ->
        {:error, {:unreachable_broker, broker_host, kind, provider}}
    end
  end

  @doc """
  What kind of address this is: `:loopback`, `:private` or `:public`.

  A name that is not an address is `:public` — this cannot resolve names,
  and a name is the normal shape of a reachable broker (a tunnel hostname,
  a deployment). `localhost` is the one name special-cased, because it is
  the mistake this module exists to catch.
  """
  @spec classify(String.t()) :: kind()
  def classify(broker_host) do
    host = broker_host |> strip_port() |> String.downcase()

    if host in ["localhost", "localhost.localdomain", "::1", "[::1]"] do
      :loopback
    else
      classify_address(host)
    end
  end

  @doc """
  The warning to print for a broker a box reaches over a public network, or
  `nil` when there is nothing to say.

  See the moduledoc: the session token rides in the clear.
  """
  @spec warning(String.t(), atom()) :: String.t() | nil
  def warning(broker_host, provider) do
    if local_provider?(provider) or classify(broker_host) != :public do
      nil
    else
      """
      The box reaches this broker over a public network, and the broker's
      listener is plaintext. Every request carries the session token in a
      Proxy-Authorization header, and that token is the authority to use
      every credential this policy names.

      Use a throwaway key, keep expires_in short, or put the hop on a
      tailnet. See Airlock.Broker.Reachability.
      """
      |> String.trim()
    end
  end

  # A box on the same machine reaches a loopback broker, which is the whole
  # reason `PLAN.md` ordered the local runner first.
  defp local_provider?(:runner), do: true
  defp local_provider?(:fake), do: true
  defp local_provider?(_provider), do: false

  defp classify_address(host) do
    case host |> unbracket() |> to_charlist() |> :inet.parse_address() do
      {:ok, address} -> classify_tuple(address)
      {:error, _reason} -> :public
    end
  end

  defp classify_tuple({127, _, _, _}), do: :loopback
  defp classify_tuple({0, 0, 0, 0}), do: :loopback
  defp classify_tuple({10, _, _, _}), do: :private
  defp classify_tuple({192, 168, _, _}), do: :private
  defp classify_tuple({169, 254, _, _}), do: :private
  defp classify_tuple({172, second, _, _}) when second >= 16 and second <= 31, do: :private
  defp classify_tuple({0, 0, 0, 0, 0, 0, 0, 1}), do: :loopback
  defp classify_tuple({0, 0, 0, 0, 0, 0, 0, 0}), do: :loopback

  defp classify_tuple({first, _, _, _, _, _, _, _}) when Bitwise.band(first, 0xFE00) == 0xFC00,
    do: :private

  defp classify_tuple({first, _, _, _, _, _, _, _}) when Bitwise.band(first, 0xFFC0) == 0xFE80,
    do: :private

  defp classify_tuple(_address), do: :public

  # `host:port`, but not the colons inside a bracketed IPv6 literal.
  defp strip_port("[" <> _ = host) do
    case String.split(host, "]", parts: 2) do
      [inside, _rest] -> inside <> "]"
      _ -> host
    end
  end

  defp strip_port(host), do: host |> String.split(":", parts: 2) |> hd()

  defp unbracket("[" <> rest), do: String.trim_trailing(rest, "]")
  defp unbracket(host), do: host
end
