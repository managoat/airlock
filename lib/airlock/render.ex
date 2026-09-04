defmodule Airlock.Render do
  @moduledoc """
  Terminal rendering for `Airlock.CLI`.

  Separate from the CLI because the record proper (M2) is an exported HTML
  file rather than a terminal, and the thing both share is the *shape* of a
  row, not the way it is drawn. Keeping the drawing out of the command
  makes the row shape the interface between them.

  Nothing here ever renders a credential. `Airlock.Policy` holds references
  rather than values, so there is no value to render; the one place a
  secret exists in this program is inside a `Managoat.Broker.Session` in
  the store, which nothing here reads.
  """

  alias Airlock.Broker
  alias Airlock.Policy
  alias Airlock.Policy.Compile
  alias Airlock.Policy.Credential

  @doc "What a policy says, and what it compiles to on both layers."
  @spec policy(Policy.t(), Path.t()) :: String.t()
  def policy(%Policy{} = policy, path) do
    """
    #{path}

    Allowed hosts (#{length(policy.allow)})
    #{bullets(policy.allow)}
    Credentials (#{length(policy.credentials)})
    #{bullets(Enum.map(policy.credentials, &credential/1))}
    Unmatched hosts: #{policy.unmatched}
    Session expiry:  #{expiry(policy.expires_in)}

    Compiles to
      the box   NetworkPolicy allow: ["<broker host>"] — the broker, and nothing else,
                so every request is forced through the chokepoint that logs it.
      the proxy #{length(policy.credentials)} credential rule(s) then #{length(policy.allow)} passthrough rule(s),
                with unmatched_host_policy: #{inspect(policy.unmatched)}.
    """
  end

  @doc "A started broker: what the box would be told, and what it may reach."
  @spec broker(Broker.t(), Policy.t()) :: String.t()
  def broker(%Broker{} = broker, %Policy{} = policy) do
    """
    broker  listening on #{broker.host}:#{broker.port}  (run #{broker.run})
    proxy   #{Broker.proxy_url(broker)}
    ca      #{ca_summary(broker)}
    box     #{box_egress(broker, policy)}
    #{placeholders(broker)}
    Try it:
      curl -x '#{Broker.proxy_url(broker)}' http://<an allowed host>/
      curl -x '#{Broker.proxy_url(broker)}' http://example.invalid/     # denied

    #{header()}
    """
  end

  @doc "One egress row, as the record's Egress tab will show it."
  @spec row(map()) :: String.t()
  def row(row) do
    [
      pad(row.verdict, 12),
      pad(row.method || "—", 7),
      pad(row.host || "—", 28),
      pad(row.path || "—", 24),
      pad(row.rule || "—", 22),
      pad(row.status || "—", 6),
      duration(row.duration_ms)
    ]
    |> Enum.join(" ")
    |> String.trim_trailing()
    |> maybe_error(row.error)
  end

  @doc "The egress table's header."
  @spec header() :: String.t()
  def header do
    [
      pad("VERDICT", 12),
      pad("METHOD", 7),
      pad("HOST", 28),
      pad("PATH", 24),
      pad("RULE", 22),
      pad("STATUS", 6),
      "TIME"
    ]
    |> Enum.join(" ")
  end

  @doc """
  A parse or start failure, in the terms of the file the user wrote.

  Every branch names the key or the entry, because a policy is a file a
  human edits and "invalid policy" is not a thing anyone can act on.
  """
  @spec error(term(), Path.t()) :: String.t()
  def error({:unreadable, path, reason}, _path),
    do: "airlock: cannot read #{path}: #{:file.format_error(reason)}"

  def error({:malformed_yaml, message}, path),
    do: "airlock: #{path} is not valid YAML: #{message}"

  def error({:yaml_timeout, ms}, path),
    do:
      "airlock: #{path} did not finish parsing in #{div(ms, 1000)}s, so it was given up on. " <>
        "An unclosed `[` or `{` makes the YAML parser spin rather than fail; check the " <>
        "brackets in this file."

  def error({:not_a_mapping, _value}, path),
    do: "airlock: #{path} is not a policy — the top level has to be a mapping of keys"

  def error({:unknown_keys, :policy, unknown, allowed}, path),
    do:
      "airlock: #{path} has #{plural(unknown, "an unknown key", "unknown keys")}: " <>
        "#{Enum.join(unknown, ", ")}. A policy takes #{Enum.join(allowed, ", ")}."

  def error({:unknown_keys, {:credential, index}, unknown, allowed}, path),
    do:
      "airlock: #{path}, credential #{index}, has " <>
        "#{plural(unknown, "an unknown key", "unknown keys")}: #{Enum.join(unknown, ", ")}. " <>
        "A credential takes #{Enum.join(allowed, ", ")}."

  def error({:missing_key, {:credential, index}, "username"}, path),
    do:
      "airlock: #{path}, credential #{index}: a basic credential needs a `username`. " <>
        "The broker's basic scheme is a username and password pair and a policy names one " <>
        "variable, so the username has to be written down — GitHub takes `x-access-token` " <>
        "and other hosts take something else, and guessing would fail as a 401."

  def error({:missing_key, {:credential, index}, key}, path),
    do: "airlock: #{path}, credential #{index}: missing `#{key}`."

  def error({:expected_string, {:credential, index}, key, value}, path),
    do:
      "airlock: #{path}, credential #{index}: `#{key}` should be a string, got #{inspect(value)}."

  def error({:expected_list, key, value}, path),
    do: "airlock: #{path}: `#{key}` should be a list, got #{inspect(value)}."

  def error({:expected_host, key, value}, path),
    do: "airlock: #{path}: `#{key}` should hold host names, got #{inspect(value)}."

  def error({:blank_allow_entry, index}, path),
    do: "airlock: #{path}: allow entry #{index} is blank."

  def error({:credential_not_a_mapping, index, value}, path),
    do: "airlock: #{path}: credential #{index} should be a mapping, got #{inspect(value)}."

  def error({:bad_scheme, index, value, allowed}, path),
    do:
      "airlock: #{path}, credential #{index}: no such scheme #{inspect(value)}. " <>
        "One of: #{Enum.join(Enum.sort(allowed), ", ")}."

  def error({:scheme_not_built, index, scheme}, path),
    do:
      "airlock: #{path}, credential #{index}: the `#{scheme}` scheme is not yet built. " <>
        "It needs a credential that is a map of keys rather than one value."

  def error({:bad_from, index, value}, path),
    do:
      "airlock: #{path}, credential #{index}: `from` should be `env:NAME`, got #{inspect(value)}."

  def error({:bad_placeholder, index, placeholder}, path),
    do:
      "airlock: #{path}, credential #{index}: the broker will refuse the placeholder " <>
        "#{inspect(placeholder)}. It has to be at least four characters, hold a letter or " <>
        "digit, and carry a boundary — `__` at either end, or a character outside " <>
        "[A-Za-z0-9_]. Substitution is a literal find-and-replace, so a short placeholder " <>
        "would rewrite parts of URLs nobody chose."

  def error({:bad_unmatched, value}, path),
    do: "airlock: #{path}: `unmatched` should be `deny` or `passthrough`, got #{inspect(value)}."

  def error({:bad_expires_in, value}, path),
    do:
      ~s(airlock: #{path}: `expires_in` should be a count and a unit — "4h", "30m", ) <>
        ~s("90s", "1d" — got #{inspect(value)}.)

  def error({:credential_not_allowed, host}, path),
    do:
      "airlock: #{path}: the credential for #{host} names a host no `allow` entry covers, " <>
        "so it can never match: the box cannot reach the host, so no request ever arrives " <>
        "for the proxy to attach it to. Add the host to `allow`, or drop the credential."

  def error({:missing_vars, names}, _path),
    do:
      "airlock: #{plural(names, "this variable is", "these variables are")} not set: " <>
        "#{Enum.join(names, ", ")}."

  def error(other, path), do: "airlock: #{path}: #{inspect(other)}"

  # ── parts ──────────────────────────────────────────────────────────────────

  # The other layer, said out loud: the box's own egress policy names the
  # broker and nothing else, and the hosts below are reachable only through
  # it. `Airlock.Policy.Compile` argues for that shape.
  defp box_egress(%Broker{} = broker, %Policy{allow: allow}) do
    %{allow: [only]} = Compile.network_policy(%Policy{}, "#{broker.host}:#{broker.port}")

    "may reach #{only} and nothing else; through it, " <>
      "#{length(allow)} host(s): #{Enum.join(allow, ", ")}"
  end

  defp credential(%Credential{} = credential) do
    from =
      case credential.from do
        {:env, name} -> "$#{name}"
        nil -> "no credential"
      end

    "#{credential.host}  #{credential.scheme}  #{from}#{placeholder_note(credential)}"
  end

  defp placeholder_note(%Credential{scheme: :substitute, placeholder: placeholder}),
    do: "  as #{placeholder}"

  defp placeholder_note(_credential), do: ""

  defp placeholders(%Broker{placeholders: placeholders}) when map_size(placeholders) == 0,
    do: "\nNo placeholders: this policy substitutes nothing.\n"

  defp placeholders(%Broker{placeholders: placeholders}) do
    lines = for {name, value} <- Enum.sort(placeholders), do: "  #{name}=#{value}"
    "\nThe box is given these, not the credentials:\n" <> Enum.join(lines, "\n") <> "\n"
  end

  # The PEM is long and is not a secret, but printing it into a terminal
  # buries everything else, and the box installs it rather than the reader.
  defp ca_summary(%Broker{} = broker) do
    pem = Broker.ca_pem(broker)
    fingerprint = :crypto.hash(:sha256, pem) |> Base.encode16(case: :lower) |> binary_part(0, 16)
    "#{byte_size(pem)} bytes, sha256:#{fingerprint}… (the box must trust this)"
  end

  defp expiry(nil), do: "none"

  defp expiry(seconds) when seconds >= 3600,
    do: "#{Float.round(seconds / 3600, 2)}h"

  defp expiry(seconds) when seconds >= 60, do: "#{div(seconds, 60)}m"
  defp expiry(seconds), do: "#{seconds}s"

  defp bullets([]), do: "  (none)\n"
  defp bullets(items), do: Enum.map_join(items, "\n", &"  #{&1}") <> "\n"

  defp maybe_error(line, nil), do: line
  defp maybe_error(line, error), do: line <> "  (#{error})"

  defp duration(nil), do: "—"
  defp duration(ms), do: "#{Float.round(ms, 1)}ms"

  defp pad(value, width), do: value |> to_string() |> String.pad_trailing(width)

  defp plural([_one], singular, _plural), do: singular
  defp plural(_many, _singular, plural), do: plural
end
