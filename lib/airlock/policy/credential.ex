defmodule Airlock.Policy.Credential do
  @moduledoc """
  One entry of a policy's `credentials:` list: a host pattern, the shape
  the credential takes on the wire, and a **reference** to where the value
  comes from.

  The value is not here and never is. `from: env:NAME` parses to
  `{:env, "NAME"}`; `Airlock.Policy.Compile.rules/2` resolves it when a
  broker session is minted. See `Airlock.Policy`.

  ## Why this is a list and not a map keyed on host

  One host may need more than one credential. `api.anthropic.com` can carry
  both a subscription token and an API key, because an org can refuse the
  OAuth token *mid-conversation* and `Managoat.Runtimes.Claude.fall_back_to_api_key/2`
  swaps to the key on a box that is already running. A session minted with
  only the OAuth rule cannot serve the fallback, so the session has to hold
  every placeholder a run might need from the start — which it cannot do if
  the schema collapsed two entries for one host into one.

  ## Fields

  | key | |
  |---|---|
  | `host` | a `Managoat.Broker.Rule` pattern: `host[:port][/path]`, `*.` wildcards and a trailing `*` on the path |
  | `scheme` | `bearer`, `basic`, `api_key`, `substitute` or `passthrough` |
  | `from` | `env:NAME` |
  | `name` | what the egress log's Rule column shows; defaults to `host` |
  | `placeholder` | `substitute` only, required |
  | `username` | `basic` only, required |
  | `header`, `prefix` | `api_key` only, optional (`Authorization` and `""`) |

  ## `:basic` requires a `username`

  `Managoat.Broker.Rule`'s `:basic` credential is a `{username, password}`
  pair and a policy names one environment variable, so the username has to
  come from somewhere. Both orders are real: GitHub takes
  `x-access-token:<token>` *and* `<token>:x-oauth-basic`, and other hosts
  take neither. Defaulting would pick one, be wrong for some host, and fail
  as a `401` the author has to work backwards from — so the key is
  required and the error says so.
  """

  alias Managoat.Broker.Injector

  @type reference_to :: {:env, String.t()}

  @type t :: %__MODULE__{
          name: String.t(),
          host: String.t(),
          scheme: Managoat.Broker.Rule.scheme(),
          from: reference_to() | nil,
          placeholder: String.t() | nil,
          username: String.t() | nil,
          header: String.t() | nil,
          prefix: String.t()
        }

  @enforce_keys [:name, :host, :scheme, :from]
  defstruct [:name, :host, :scheme, :from, :placeholder, :username, :header, prefix: ""]

  @keys ~w(host scheme from name placeholder username header prefix)
  @schemes %{
    "bearer" => :bearer,
    "basic" => :basic,
    "api_key" => :api_key,
    "substitute" => :substitute,
    "passthrough" => :passthrough
  }

  @doc "Parse one `credentials:` entry. `index` only names it in errors."
  @spec parse(term(), non_neg_integer()) :: {:ok, t()} | {:error, term()}
  def parse(entry, index) when is_map(entry) do
    with :ok <- known_keys(entry, index),
         {:ok, host} <- fetch_string(entry, "host", index),
         {:ok, scheme} <- fetch_scheme(entry, index),
         {:ok, from} <- fetch_from(entry, index) do
      credential = %__MODULE__{
        name: Map.get(entry, "name") || host,
        host: host,
        scheme: scheme,
        from: from,
        placeholder: Map.get(entry, "placeholder"),
        username: Map.get(entry, "username"),
        header: Map.get(entry, "header"),
        prefix: Map.get(entry, "prefix", "")
      }

      validate(credential, index)
    end
  end

  def parse(entry, index), do: {:error, {:credential_not_a_mapping, index, entry}}

  @doc """
  Is this credential's host reachable under `allow`?

  Compares host parts only: a credential's pattern may pin a port and a
  path (`github.com/managoat/*`), while an `allow` entry is a domain, and
  it is the domain the box's egress policy is written in terms of.
  """
  @spec covered_by?(t(), [String.t()]) :: boolean()
  def covered_by?(%__MODULE__{host: pattern}, allow) when is_list(allow) do
    host = host_part(pattern)

    # A wildcard credential host is not a host, so it cannot be asked
    # whether an allow entry matches it; it is covered when the same
    # wildcard (or a broader one) is allowed outright.
    if String.starts_with?(host, "*.") do
      Enum.any?(allow, &(host_part(&1) |> String.downcase() == String.downcase(host)))
    else
      Enum.any?(allow, &Injector.host_matches?(host_part(&1), host, 443))
    end
  end

  @doc "The host part of a rule pattern: no port, no path."
  @spec host_part(String.t()) :: String.t()
  def host_part("[" <> _ = pattern) do
    # A bracketed IPv6 literal: the port separator is the colon after `]`.
    case String.split(pattern, "]", parts: 2) do
      [inside, rest] -> "#{inside}]" <> bracketed_suffix(rest)
      _ -> pattern
    end
  end

  def host_part(pattern) do
    pattern |> String.split("/", parts: 2) |> hd() |> String.split(":", parts: 2) |> hd()
  end

  defp bracketed_suffix(rest) do
    case rest do
      ":" <> port -> ":" <> (port |> String.split("/", parts: 2) |> hd())
      _ -> ""
    end
  end

  # ── parsing ────────────────────────────────────────────────────────────────

  defp known_keys(entry, index) do
    case entry |> Map.keys() |> Enum.reject(&(&1 in @keys)) |> Enum.sort() do
      [] -> :ok
      unknown -> {:error, {:unknown_keys, {:credential, index}, unknown, @keys}}
    end
  end

  defp fetch_string(entry, key, index) do
    case Map.get(entry, key) do
      value when is_binary(value) and value != "" -> {:ok, value}
      nil -> {:error, {:missing_key, {:credential, index}, key}}
      other -> {:error, {:expected_string, {:credential, index}, key, other}}
    end
  end

  defp fetch_scheme(entry, index) do
    case Map.get(entry, "scheme") do
      nil ->
        {:error, {:missing_key, {:credential, index}, "scheme"}}

      "custom" ->
        {:error, {:scheme_not_built, index, "custom"}}

      value when is_binary(value) ->
        case Map.fetch(@schemes, value) do
          {:ok, scheme} -> {:ok, scheme}
          :error -> {:error, {:bad_scheme, index, value, Map.keys(@schemes)}}
        end

      other ->
        {:error, {:expected_string, {:credential, index}, "scheme", other}}
    end
  end

  # `:passthrough` carries no credential, so it needs no `from:` — it is
  # how a host is allowed under `deny`, which is a thing a policy might
  # want to say explicitly about a host it also lists in `allow`.
  defp fetch_from(entry, index) do
    case {Map.get(entry, "from"), Map.get(entry, "scheme")} do
      {nil, "passthrough"} -> {:ok, nil}
      {"env:" <> name, _} when name != "" -> {:ok, {:env, name}}
      {nil, _} -> {:error, {:missing_key, {:credential, index}, "from"}}
      {other, _} -> {:error, {:bad_from, index, other}}
    end
  end

  # ── validation ─────────────────────────────────────────────────────────────

  defp validate(%__MODULE__{scheme: :substitute, placeholder: nil}, index),
    do: {:error, {:missing_key, {:credential, index}, "placeholder"}}

  defp validate(%__MODULE__{scheme: :substitute, placeholder: placeholder} = credential, index) do
    if Injector.valid_placeholder?(placeholder) do
      {:ok, credential}
    else
      {:error, {:bad_placeholder, index, placeholder}}
    end
  end

  defp validate(%__MODULE__{scheme: :basic, username: nil}, index),
    do: {:error, {:missing_key, {:credential, index}, "username"}}

  defp validate(%__MODULE__{} = credential, _index), do: {:ok, credential}
end
