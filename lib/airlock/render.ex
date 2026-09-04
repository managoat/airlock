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
  A run's progress, one line per stage, to stderr so the record on stdout
  stays a record.
  """
  @spec stage(String.t(), term()) :: :ok
  def stage(name, :started), do: IO.puts(:stderr, "  #{pad(name, 10)} …")
  def stage(name, :done), do: IO.puts(:stderr, "  #{pad(name, 10)} ok")

  def stage("broker", {:ready, host}), do: IO.puts(:stderr, "  #{pad("broker", 10)} #{host}")

  def stage(name, {:skipped, provider}),
    do:
      IO.puts(
        :stderr,
        "  #{pad(name, 10)} SKIPPED — #{provider} boxes cannot be sealed, and --unsealed was given"
      )

  def stage(name, {:failed, reason}),
    do: IO.puts(:stderr, "  #{pad(name, 10)} failed: #{inspect(reason)}")

  def stage(_name, _status), do: :ok

  @doc """
  The record of a finished run, for the terminal: what the agent said, and
  every request it made.

  A **summary**, not the record. The record is `Airlock.Record`'s file, and
  it holds all four of `PLAN.md`'s tabs; this is the part worth reading
  without opening anything, printed where the run was started. The two are
  deliberately not the same artefact — a summary you have to open a browser
  for is not one, and a record that scrolls away is not one either.
  """
  @spec record(map()) :: String.t()
  def record(result) do
    """

    ── Transcript ──────────────────────────────────────────────────────────

    #{Airlock.Transcript.text(result.transcript)}

    #{tool_summary(result.transcript)}stopped: #{result.transcript.stop_reason || "—"}#{usage(result.transcript.usage)}

    ── Egress ──────────────────────────────────────────────────────────────

    #{header()}
    #{egress(result.egress)}

    box #{result.box} (#{if result.sealed?, do: "sealed", else: "UNSEALED"}), destroyed. run #{result.run}
    """
  end

  @doc "Airlock's boxes on a provider account, and what to do about them."
  @spec boxes([Airlock.Boxes.box()], atom()) :: String.t()
  def boxes([], provider), do: "No Airlock boxes on the #{provider} account."

  def boxes(boxes, provider) do
    """
    #{length(boxes)} Airlock box(es) on the #{provider} account:

    #{Enum.map_join(boxes, "\n", &"  #{pad(&1.name, 28)} #{&1.status}")}

    A run destroys its own box, so these outlived one — most likely a run
    that was interrupted before its destroy step. `airlock reap --yes`
    destroys them.
    """
  end

  @doc """
  What `reap` refuses to do without being told twice.

  From out here a box someone is working on looks exactly like an orphan:
  the account view is names, and a status does not say whose.
  """
  @spec reap_refused([Airlock.Boxes.box()], atom()) :: String.t()
  def reap_refused(boxes, provider) do
    boxes(boxes, provider) <>
      "\nairlock: reap destroys boxes and will not do it unasked. " <>
      "Pass --yes if these are yours to destroy."
  end

  @doc "What a reap did, one line per box."
  @spec reaped([{:ok | :refused | {:error, term()}, String.t()}]) :: String.t()
  def reaped(results) do
    Enum.map_join(results, "\n", fn
      {:ok, name} -> "  #{pad(name, 28)} destroyed"
      {:refused, name} -> "  #{pad(name, 28)} left alone — not a name Airlock minted"
      {{:error, reason}, name} -> "  #{pad(name, 28)} failed: #{inspect(reason)}"
    end)
  end

  @doc "Why the account could not be read."
  @spec boxes_error(term()) :: String.t()
  def boxes_error(:truncated) do
    """
    airlock: the provider would not give a complete list of the account's
    sandboxes, and returned :truncated rather than a partial one that looks
    whole. Reaping against half an account is worse than not reaping, so
    this stops here.
    """
  end

  def boxes_error({:provider_not_configured, _provider, _var} = reason),
    do: run_error(reason, "")

  def boxes_error(reason), do: run_error(reason, "")

  @doc "Why a run stopped, in terms someone can act on."
  @spec run_error(term(), Path.t()) :: String.t()
  def run_error({:cannot_seal, provider}, _path) do
    """
    airlock: a #{provider} box cannot have a network policy applied, so this
    run would not have been contained. Managoat.Runner.Adapter refuses
    apply_network_policy/2 outright — "the machine is the user's and so is
    its network" — and Airlock will not produce a record that claims
    containment it did not have.

    Use a provider that can be sealed (sprites, e2b, daytona), or pass
    --unsealed to say you accept an uncontained box. See NOTES-M0.md §1.
    """
  end

  def run_error({:unreachable_broker, host, kind, provider}, _path) do
    """
    airlock: a #{provider} box cannot reach #{host} — that is a #{kind} address,
    and the box is not on this machine.

    The broker is a listener the box dials out to, so it needs an address on
    the box's network. A raw TCP tunnel works; an HTTP reverse proxy does
    not, because the proxy protocol is CONNECT.

      ngrok tcp <the broker's port>
      airlock run ... --broker-host 4.tcp.ngrok.io:19482

    Read Airlock.Broker.Reachability first: the listener is plaintext.
    """
  end

  def run_error({:provider_not_configured, :sprites, var}, _path) do
    """
    airlock: no Sprites credentials, so there is no box to run on.

    Either sign in with the CLI — `sprite login` — and Airlock will read
    the token out of ~/.sprites and your login keychain, or set #{var}
    in your environment.
    """
  end

  def run_error({:provider_not_configured, provider, var}, _path),
    do: "airlock: no credentials for #{provider}. Set #{var} in your environment."

  def run_error(:no_runner_connected, _path) do
    """
    airlock: no runner is connected, so there is no local box to run on.

    A runner is a daemon on your machine that dials in to Airlock and
    presents itself as a sandbox provider. Airlock ships the endpoint it
    dials into (Airlock.Box.Endpoint) but not the daemon: that is a Go
    binary in Fountain's private CLI and is not one of the nine libraries.
    See NOTES-M0.md §2.

    Use --provider sprites (or e2b, or daytona) instead.
    """
  end

  def run_error({:create, reason}, path), do: run_error(reason, path)

  def run_error({:denied, {:http, 401, _body}}, _path),
    do: "airlock: the provider refused those credentials (401). Check the token."

  def run_error({:denied, {:http, 403, _body}}, _path),
    do: "airlock: the provider refused the request (403). Check the token's scope."

  def run_error({:unknown_runtime, runtime, supported}, _path),
    do: "airlock: no such runtime #{inspect(runtime)}. One of: #{Enum.join(supported, ", ")}."

  def run_error({:bad_permissions, verdict, allowed}, _path),
    do:
      "airlock: no such permission verdict #{inspect(verdict)}. " <>
        "One of: #{Enum.join(allowed, ", ")}."

  def run_error({:bad_provider, provider, allowed}, _path),
    do: "airlock: no such provider #{inspect(provider)}. One of: #{Enum.join(allowed, ", ")}."

  def run_error({:bad_flags, flags}, _path),
    do: "airlock: no such option: #{Enum.join(flags, ", ")}."

  def run_error({:unexpected_args, args}, _path),
    do: "airlock: unexpected argument: #{Enum.join(args, " ")}."

  def run_error({:turn_timeout, _transcript}, _path),
    do: "airlock: the turn did not finish in time. The box was destroyed."

  def run_error({:adapter_exited, code, stderr}, _path),
    do:
      "airlock: the agent adapter exited (#{code}) before the turn ended." <>
        if(stderr == "", do: "", else: "\n\n" <> stderr)

  def run_error(reason, path), do: error(reason, path)

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

  def error({:bad_provider, _provider, _allowed} = reason, path), do: run_error(reason, path)
  def error({:bad_permissions, _verdict, _allowed} = reason, path), do: run_error(reason, path)
  def error({:bad_flags, _flags} = reason, path), do: run_error(reason, path)
  def error({:unexpected_args, _args} = reason, path), do: run_error(reason, path)

  def error({:missing_vars, names}, _path),
    do:
      "airlock: #{plural(names, "this variable is", "these variables are")} not set: " <>
        "#{Enum.join(names, ", ")}."

  def error(other, path), do: "airlock: #{path}: #{inspect(other)}"

  # ── parts ──────────────────────────────────────────────────────────────────

  defp egress([]), do: "  (no requests — the agent reached nothing)"
  defp egress(rows), do: Enum.map_join(rows, "\n", &row/1)

  defp tool_summary(transcript) do
    case length(Airlock.Transcript.of_kind(transcript, :tool_use)) do
      0 -> ""
      n -> "#{n} tool call(s). "
    end
  end

  defp usage(nil), do: ""

  defp usage(usage) do
    " · " <>
      Enum.map_join(usage, ", ", fn {key, value} -> "#{key} #{value}" end)
  end

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
