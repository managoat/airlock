defmodule Airlock.Policy do
  @moduledoc """
  The thing a user actually authors: the complete list of hosts a job may
  reach, and which credential goes to which host.

  A policy is parsed from YAML, validated, and compiled by
  `Airlock.Policy.Compile` onto the two layers that enforce it — a
  `Managoat.Sandbox.NetworkPolicy` on the box and a list of
  `Managoat.Broker.Rule` at the proxy. Those are different layers and the
  compiler's moduledoc is where the difference is written down.

  ## The file

      allow:
        - github.com
        - registry.npmjs.org
        - api.stripe.com

      credentials:
        - host: api.stripe.com
          scheme: bearer
          from: env:STRIPE_RESTRICTED_KEY

        - host: api.anthropic.com
          scheme: substitute
          placeholder: "PLACEHOLDER-ANTHROPIC"
          from: env:ANTHROPIC_API_KEY

      unmatched: deny
      expires_in: "4h"

  ## What this struct does *not* hold

  A credential's **value**. `from:` is parsed into a reference — `{:env,
  "STRIPE_RESTRICTED_KEY"}` — and nothing here ever reads it.
  `Airlock.Policy.Compile.rules/2` resolves references against a variable
  map at the moment a broker session is minted, which is the only place a
  secret exists in this program.

  That split is not tidiness. The record is the product, a policy is the
  thing a user checks into a repository, and both get printed; a struct
  that cannot hold a secret cannot leak one. `policy_test.exs` asserts it
  on the struct rather than trusting the convention.

  ## Validation

  Parsing refuses the mistakes that would otherwise be silent, because
  every one of them fails as a *wrong answer* rather than an error:

    * an unknown top-level key, or an unknown key in a credential entry — a
      policy whose `allow:` is spelled `allowed:` has an empty allow list,
      which is a legal policy meaning "deny everything", so the typo would
      read as a deliberate lockdown;
    * a credential naming a host no `allow` entry covers, which can never
      match anything and is therefore a credential the author believes is
      attached and is not;
    * a `:substitute` placeholder the broker will refuse
      (`Managoat.Broker.Injector.valid_placeholder?/1` — at least four
      characters, holding a letter or digit, carrying a boundary). The
      library asks a host to check this where the session is built rather
      than on every request that matches, and a policy file is where it is
      written;
    * a `:basic` credential with no `username`. See `Airlock.Policy.Credential`.

  ## Not yet built

  The `:custom` scheme (`Managoat.Broker.Rule`'s templated multi-header
  form) is refused with an error naming it. It needs a credential shape
  that is a map of keys rather than one value, and nothing has wanted it.
  """

  alias Airlock.Policy.Credential

  @type unmatched :: :deny | :passthrough

  @type t :: %__MODULE__{
          allow: [String.t()],
          credentials: [Credential.t()],
          unmatched: unmatched(),
          expires_in: pos_integer() | nil
        }

  defstruct allow: [], credentials: [], unmatched: :deny, expires_in: nil

  @top_level_keys ~w(allow credentials unmatched expires_in)

  # How long a policy file gets to parse. See `read_yaml/1`.
  @parse_timeout 5_000

  @doc """
  Parse and validate a policy from a YAML string.

  Every error is returned rather than raised, as `{:error, reason}`, and
  `Airlock.Policy.Error.message/1` renders one for a terminal.
  """
  @spec parse(String.t()) :: {:ok, t()} | {:error, term()}
  def parse(yaml) when is_binary(yaml) do
    with {:ok, raw} <- read_yaml(yaml),
         {:ok, map} <- as_map(raw),
         :ok <- known_keys(map, @top_level_keys, :policy),
         {:ok, allow} <- parse_allow(map),
         {:ok, credentials} <- parse_credentials(map),
         {:ok, unmatched} <- parse_unmatched(map),
         {:ok, expires_in} <- parse_expires_in(map),
         policy = %__MODULE__{
           allow: allow,
           credentials: credentials,
           unmatched: unmatched,
           expires_in: expires_in
         },
         :ok <- validate_coverage(policy) do
      {:ok, policy}
    end
  end

  @doc "Parse and validate the policy at `path`."
  @spec load(Path.t()) :: {:ok, t()} | {:error, term()}
  def load(path) do
    case File.read(path) do
      {:ok, yaml} -> parse(yaml)
      {:error, reason} -> {:error, {:unreadable, path, reason}}
    end
  end

  @doc """
  Every environment variable this policy needs to mint a session.

  Sorted and de-duplicated, so a caller can report every one that is
  missing in a single attempt rather than one per attempt — the property
  `Managoat.Substitution` exists to give a config file, applied here to a
  policy's credential references.
  """
  @spec required_vars(t()) :: [String.t()]
  def required_vars(%__MODULE__{credentials: credentials}) do
    credentials
    |> Enum.flat_map(fn
      %Credential{from: {:env, name}} -> [name]
      %Credential{from: nil} -> []
    end)
    |> Enum.uniq()
    |> Enum.sort()
  end

  # ── yaml ───────────────────────────────────────────────────────────────────

  # Bounded, because some malformed input does not come back.
  #
  # `YamlElixir.read_from_string("allow: [a.com\ncredentials:")` — an
  # unclosed flow sequence — spins inside yamerl rather than returning an
  # error, indefinitely and using a core. Unbounded, a typo in a policy
  # file hangs `airlock` with no output and nothing to read.
  #
  # This is the one place `Task.async/1` is right despite `CLAUDE.md`'s
  # rule against it: that rule is about fire-and-forget work nothing
  # awaits, and this awaits, yields, and brutally kills what did not
  # finish. A parse that runs longer than a human would wait is a parse
  # that is not going to finish.
  defp read_yaml(yaml) do
    task = Task.async(fn -> YamlElixir.read_from_string(yaml) end)

    case Task.yield(task, @parse_timeout) || Task.shutdown(task, :brutal_kill) do
      {:ok, {:ok, raw}} -> {:ok, raw}
      {:ok, {:error, %{message: message}}} -> {:error, {:malformed_yaml, message}}
      {:ok, {:error, other}} -> {:error, {:malformed_yaml, inspect(other)}}
      {:exit, reason} -> {:error, {:malformed_yaml, inspect(reason)}}
      nil -> {:error, {:yaml_timeout, @parse_timeout}}
    end
  end

  # An empty file parses as nil, which is a policy with no allow list —
  # legal, and meaning deny everything. Anything that is not a mapping is
  # not a policy at all.
  defp as_map(nil), do: {:ok, %{}}
  defp as_map(map) when is_map(map), do: {:ok, map}
  defp as_map(other), do: {:error, {:not_a_mapping, other}}

  defp known_keys(map, allowed, where) do
    case map |> Map.keys() |> Enum.reject(&(&1 in allowed)) |> Enum.sort() do
      [] -> :ok
      unknown -> {:error, {:unknown_keys, where, unknown, allowed}}
    end
  end

  # ── allow ──────────────────────────────────────────────────────────────────

  defp parse_allow(map) do
    case Map.get(map, "allow") do
      nil -> {:ok, []}
      list when is_list(list) -> allow_entries(list)
      other -> {:error, {:expected_list, "allow", other}}
    end
  end

  defp allow_entries(list) do
    Enum.reduce_while(list, {:ok, []}, fn
      entry, {:ok, acc} when is_binary(entry) ->
        case String.trim(entry) do
          "" -> {:halt, {:error, {:blank_allow_entry, length(acc)}}}
          host -> {:cont, {:ok, [host | acc]}}
        end

      other, {:ok, _acc} ->
        {:halt, {:error, {:expected_host, "allow", other}}}
    end)
    |> case do
      {:ok, acc} -> {:ok, acc |> Enum.reverse() |> Enum.uniq()}
      error -> error
    end
  end

  # ── credentials ────────────────────────────────────────────────────────────

  defp parse_credentials(map) do
    case Map.get(map, "credentials") do
      nil -> {:ok, []}
      list when is_list(list) -> credential_entries(list)
      other -> {:error, {:expected_list, "credentials", other}}
    end
  end

  defp credential_entries(list) do
    list
    |> Enum.with_index()
    |> Enum.reduce_while({:ok, []}, fn {entry, index}, {:ok, acc} ->
      case Credential.parse(entry, index) do
        {:ok, credential} -> {:cont, {:ok, [credential | acc]}}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
    |> case do
      {:ok, acc} -> {:ok, Enum.reverse(acc)}
      error -> error
    end
  end

  # ── unmatched ──────────────────────────────────────────────────────────────

  # The default is `:deny` and it is the only value that makes the allow
  # list mean anything: under `:passthrough` the proxy forwards a request
  # to a host no rule names, and since the box's only egress is the proxy
  # (see `Airlock.Policy.Compile`) that is the whole allow list disabled.
  # It is still accepted, because it is the library's field and a job that
  # deliberately wants an open proxy is the author's call — but it has to
  # be written down to happen.
  defp parse_unmatched(map) do
    case Map.get(map, "unmatched") do
      nil -> {:ok, :deny}
      "deny" -> {:ok, :deny}
      "passthrough" -> {:ok, :passthrough}
      other -> {:error, {:bad_unmatched, other}}
    end
  end

  # ── expires_in ─────────────────────────────────────────────────────────────

  @units %{"s" => 1, "m" => 60, "h" => 3600, "d" => 86_400}

  defp parse_expires_in(map) do
    case Map.get(map, "expires_in") do
      nil ->
        {:ok, nil}

      value when is_binary(value) ->
        parse_duration(value)

      other ->
        {:error, {:bad_expires_in, other}}
    end
  end

  defp parse_duration(value) do
    with %{"count" => count, "unit" => unit} <-
           Regex.named_captures(~r/\A(?<count>\d+)(?<unit>[smhd])\z/, String.trim(value)),
         {number, ""} when number > 0 <- Integer.parse(count) do
      {:ok, number * Map.fetch!(@units, unit)}
    else
      _ -> {:error, {:bad_expires_in, value}}
    end
  end

  # ── coverage ───────────────────────────────────────────────────────────────

  # A credential naming a host outside `allow` is a rule that can never
  # match: the box cannot reach the host, so no request ever arrives for
  # the proxy to attach the credential to. Nothing fails — the author just
  # believes a credential is in play that is not. PLAN.md files this under
  # M1; it is here because it costs a dozen lines and because the failure
  # it prevents is invisible.
  defp validate_coverage(%__MODULE__{allow: allow, credentials: credentials}) do
    credentials
    |> Enum.reject(&Credential.covered_by?(&1, allow))
    |> case do
      [] -> :ok
      [%Credential{} = uncovered | _] -> {:error, {:credential_not_allowed, uncovered.host}}
    end
  end
end
