defmodule Airlock.Record do
  @moduledoc """
  The record: one self-contained HTML file describing everything a run did.

  M2. `PLAN.md` calls this the thing that turns a utility into a product,
  and the reason is in the README's own claim — *you get a record of
  everything it did*. M0 left that as a terminal table, and you cannot hand
  someone stdout.

  ## A file, not a server

  Settled question 3. The product claim is that the record is **handable**,
  and a file is handable in a way a localhost route is not: it survives the
  process, it attaches to an email, it goes in a ticket, it can be diffed
  against last week's. So this module writes one file with everything in
  it — no stylesheet to fetch, no script to run, no font, no CDN. What is
  on disk is the whole record.

  That constraint is also what decides the tabs are CSS and not JavaScript.
  Four `input[type=radio]` and a sibling selector; the page works with
  scripting off, in a text browser's "save page" and in whatever a
  reviewer's mail client renders.

  ## What is in it, and what is not

  Four tabs, `PLAN.md`'s four:

    * **Transcript** — `Managoat.ACP.Blocks` blocks, in order, never a
      runtime dialect. `Airlock.Transcript` is what parses them and the
      rule it enforces is that this module never sees a vendor's format;
    * **Egress** — every request the proxy decided about, with the verdict
      and the rule that decided it. `Airlock.Egress.rows/1`;
    * **Tools** — every tool call the agent made, paired with its result,
      how long it took, and what the turn cost in tokens;
    * **Changes** — what the agent left behind: the files it touched and
      the patch, taken against the state the box was in when the turn
      started. `Airlock.Changes`.

  **No credential is ever rendered**, and the reason it is safe to say that
  flatly is structural rather than careful: `Airlock.Policy` holds
  references (`{:env, "STRIPE_KEY"}`) and not values, `Airlock.Egress` rows
  carry no headers and no bodies because the library never puts them in the
  event, and the one place a secret exists in this program is inside a
  `Managoat.Broker.Session` in the store, which nothing here reads. The
  broker's **session token** is a secret and is likewise never written: the
  proxy URL does not appear in the record, only the address the box was
  sealed to.

  ## Everything is escaped, because everything is untrusted

  A transcript is an agent's output, a tool result is whatever a command on
  the box printed, and a hostname in an egress row is whatever the agent
  tried to reach. All three are attacker-reachable in the threat model this
  product exists for — the record of a run that went wrong is exactly the
  one someone opens — so every interpolated value goes through `escape/1`
  and nothing is rendered as markup. Agent text is `white-space: pre-wrap`
  escaped text, never rendered markdown: rendering it would mean an HTML
  sanitiser, and the record is not worth a sanitiser.
  """

  alias Airlock.Egress
  alias Airlock.Policy
  alias Airlock.Policy.Credential
  alias Airlock.Transcript

  @typedoc """
  A finished run, as `Airlock.Run.start/1` returns it. Everything the
  record shows comes from here; nothing is fetched at write time, because
  the box is destroyed by then.
  """
  @type result :: %{
          required(:run) => String.t(),
          required(:transcript) => Transcript.t(),
          required(:egress) => [Egress.row()],
          required(:box) => String.t(),
          required(:sealed?) => boolean(),
          optional(:prompt) => String.t(),
          optional(:policy) => Policy.t(),
          optional(:policy_path) => Path.t(),
          optional(:provider) => atom(),
          optional(:runtime) => String.t(),
          optional(:sealed_to) => String.t(),
          optional(:started_at) => DateTime.t(),
          optional(:finished_at) => DateTime.t(),
          optional(:changes) => {:ok, map()} | {:error, term()}
        }

  @doc """
  Write `result` to a self-contained HTML file and return its path.

  `:path` names the file; the default is `airlock-<run>.html` in the
  current directory, because a run id is the one name that is already
  unique and already in the record.
  """
  @spec write(result(), keyword()) :: {:ok, Path.t()} | {:error, term()}
  def write(result, opts \\ []) do
    path = Keyword.get(opts, :path) || default_path(result)

    case File.write(path, html(result)) do
      :ok -> {:ok, path}
      {:error, reason} -> {:error, {:record_unwritable, path, reason}}
    end
  end

  @doc "Where a run's record lands when the caller names no path."
  @spec default_path(result()) :: Path.t()
  def default_path(%{run: run}), do: "airlock-#{run}.html"

  @doc "The whole record, as one HTML document."
  @spec html(result()) :: String.t()
  def html(result) do
    """
    <!doctype html>
    <html lang="en"><head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Airlock record #{escape(result.run)}</title>
    <style>#{css()}</style>
    </head><body>
    #{header(result)}
    #{tabs(result)}
    #{footer(result)}
    </body></html>
    """
  end

  # ── header ─────────────────────────────────────────────────────────────────

  defp header(result) do
    """
    <header>
      <div class="title">
        <h1>Airlock record</h1>
        <code class="run">#{escape(result.run)}</code>
      </div>
      #{claim(result)}
      <dl class="meta">
        #{meta_rows(result)}
      </dl>
      #{prompt(result)}
    </header>
    """
  end

  # The one sentence the record exists to support, stated in the terms of
  # this run. A record of an unsealed run says the opposite in as many
  # words rather than omitting the line — a reader who does not see a
  # containment claim concludes there was one.
  defp claim(result) do
    counts = counts(result.egress)

    if result.sealed? do
      """
      <p class="claim sealed">The box reached #{escape(sealed_to(result))} and nothing else.
      #{count_phrase(counts)}</p>
      """
    else
      """
      <p class="claim unsealed"><strong>This box was not sealed.</strong> No network policy was
      applied, so the box could reach the network without going through the proxy, and requests
      that did not go through it are not below. #{count_phrase(counts)}</p>
      """
    end
  end

  defp count_phrase(counts) do
    parts =
      [
        {:injected, "carried a credential the box never held"},
        {:passthrough, "reached an allowed host untouched"},
        {:denied, "were refused"},
        {:malformed, "could not be read by the recorder"}
      ]
      |> Enum.filter(fn {verdict, _} -> counts[verdict] > 0 end)
      |> Enum.map(fn {verdict, phrase} -> "#{counts[verdict]} #{phrase}" end)

    case parts do
      [] -> "It made no requests."
      parts -> "Of #{counts.total} request(s), " <> sentence(parts) <> "."
    end
  end

  defp sentence([one]), do: one
  defp sentence(parts), do: Enum.join(Enum.drop(parts, -1), ", ") <> " and " <> List.last(parts)

  defp meta_rows(result) do
    [
      {"Box", "#{result.box} (#{provider(result)})"},
      {"Sealed to", if(result.sealed?, do: sealed_to(result), else: "— not sealed")},
      {"Runtime", Map.get(result, :runtime, "—")},
      {"Policy", Map.get(result, :policy_path, "—")},
      {"Started", timestamp(Map.get(result, :started_at))},
      {"Took", duration(result)},
      {"Ended", result.transcript.stop_reason || "—"},
      {"Tokens", usage(result.transcript.usage)}
    ]
    |> Enum.map_join("\n", fn {label, value} ->
      "<div><dt>#{escape(label)}</dt><dd>#{escape(value)}</dd></div>"
    end)
  end

  defp prompt(%{prompt: prompt}) when is_binary(prompt) and prompt != "" do
    """
    <div class="prompt"><span class="label">Prompt</span><pre>#{escape(prompt)}</pre></div>
    """
  end

  defp prompt(_result), do: ""

  # ── tabs ───────────────────────────────────────────────────────────────────

  @panels [
    {"transcript", "Transcript"},
    {"egress", "Egress"},
    {"tools", "Tools"},
    {"changes", "Changes"}
  ]

  defp tabs(result) do
    inputs =
      @panels
      |> Enum.with_index()
      |> Enum.map_join("\n", fn {{id, _label}, index} ->
        ~s(<input type="radio" name="tab" id="tab-#{id}"#{if index == 0, do: " checked"}>)
      end)

    nav =
      Enum.map_join(@panels, "\n", fn {id, label} ->
        ~s(<label for="tab-#{id}">#{escape(label)}#{badge(id, result)}</label>)
      end)

    """
    <div class="tabs">
    #{inputs}
    <nav>#{nav}</nav>
    <section class="panel" id="panel-transcript">#{transcript_panel(result)}</section>
    <section class="panel" id="panel-egress">#{egress_panel(result)}</section>
    <section class="panel" id="panel-tools">#{tools_panel(result)}</section>
    <section class="panel" id="panel-changes">#{changes_panel(result)}</section>
    </div>
    """
  end

  # Only a tab with something in it is counted. A badge on an unbuilt tab
  # would say the panel behind it holds that many rows, and it holds a
  # placeholder.
  defp badge("egress", result), do: count_badge(length(result.egress))
  defp badge("tools", result), do: count_badge(length(Transcript.tool_calls(result.transcript)))

  defp badge("changes", %{changes: {:ok, %{files: files}}}), do: count_badge(length(files))
  defp badge(_id, _result), do: ""

  defp count_badge(0), do: ""
  defp count_badge(n), do: ~s(<span class="count">#{n}</span>)

  # ── transcript ─────────────────────────────────────────────────────────────

  defp transcript_panel(%{transcript: %Transcript{blocks: []}} = result) do
    empty("The agent produced no output.", stderr_details(result))
  end

  defp transcript_panel(%{transcript: transcript} = result) do
    results = tool_results(transcript)

    body =
      transcript
      |> group_text()
      # A `:tool_result` is rendered inside the `:tool_use` it belongs to,
      # so the standalone block is dropped rather than shown twice.
      |> Enum.reject(&(Map.get(&1, :kind) == :tool_result))
      |> Enum.map_join("\n", &block(&1, results))

    body <> stderr_details(result)
  end

  # Adjacent `:text` chunks are one message; see `Airlock.Transcript.messages/1`.
  # Adjacent `:thinking` chunks are one thought for the same reason.
  defp group_text(%Transcript{blocks: blocks}) do
    blocks
    |> Enum.chunk_by(&chunkable(Map.get(&1, :kind)))
    |> Enum.flat_map(fn
      [%{kind: kind} | _] = run when kind in [:text, :thinking] ->
        [%{kind: kind, body: Enum.map_join(run, "", &(Map.get(&1, :body) || ""))}]

      run ->
        run
    end)
  end

  defp chunkable(kind) when kind in [:text, :thinking], do: kind
  defp chunkable(_kind), do: :other

  defp block(%{kind: :text, body: body}, _results),
    do: ~s(<div class="msg agent"><pre>#{escape(body)}</pre></div>)

  defp block(%{kind: :thinking, body: body}, _results) do
    """
    <details class="msg thinking"><summary>Thinking</summary><pre>#{escape(body)}</pre></details>
    """
  end

  defp block(%{kind: :tool_use} = use, results) do
    result = Map.get(results, use[:id])

    """
    <div class="tool#{if result && result[:error?], do: " failed", else: ""}">
      <div class="tool-head">
        <span class="tool-name">#{escape(use[:name] || "tool")}</span>
        <span class="tool-summary">#{escape(use[:summary] || "")}</span>
        #{tool_status(result)}
      </div>
      #{pre_details("Input", use[:body])}
      #{pre_details("Output", result && result[:body])}
    </div>
    """
  end

  defp block(%{kind: :permission_request} = request, _results) do
    options =
      request
      |> Map.get(:options, [])
      |> Enum.map_join(", ", &escape(Map.get(&1, "name") || Map.get(&1, "optionId") || "?"))

    """
    <div class="tool permission">
      <div class="tool-head">
        <span class="tool-name">#{escape(request[:name] || "permission")}</span>
        <span class="tool-summary">#{escape(request[:summary] || "")}</span>
        <span class="status denied">asked</span>
      </div>
      <p class="note">The agent asked for permission#{if options == "", do: "", else: " (#{options})"}.
      Nobody was attached to answer, so it was denied.</p>
    </div>
    """
  end

  defp block(%{kind: :raw, body: body}, _results),
    do: ~s(<div class="msg raw"><pre>#{escape(body)}</pre></div>)

  defp block(block, _results),
    do: ~s(<div class="msg raw"><pre>#{escape(inspect(block))}</pre></div>)

  defp tool_status(nil), do: ~s(<span class="status open">no result</span>)
  defp tool_status(%{error?: true}), do: ~s(<span class="status denied">failed</span>)
  defp tool_status(_result), do: ~s(<span class="status ok">ok</span>)

  defp pre_details(_label, nil), do: ""
  defp pre_details(_label, ""), do: ""

  defp pre_details(label, body),
    do: ~s(<details><summary>#{escape(label)}</summary><pre>#{escape(body)}</pre></details>)

  # ── egress ─────────────────────────────────────────────────────────────────

  defp egress_panel(%{egress: []} = result) do
    empty(
      "The agent made no requests through the proxy.",
      policy_details(result)
    )
  end

  defp egress_panel(%{egress: rows} = result) do
    """
    <p class="note">Every request the proxy decided about, oldest first. A
    <em>verdict</em> is read from the scheme of the rule that matched:
    <strong>injected</strong> means a credential the box never held was attached,
    <strong>passthrough</strong> means the request reached an allowed host untouched, and
    <strong>denied</strong> means the policy named no rule for it.</p>
    <div class="scroll"><table class="egress">
      <thead><tr>
        <th>Verdict</th><th>Method</th><th>Host</th><th>Path</th>
        <th>Rule</th><th>Status</th><th class="num">Time</th>
      </tr></thead>
      <tbody>#{Enum.map_join(rows, "\n", &egress_row/1)}</tbody>
    </table></div>
    #{policy_details(result)}
    """
  end

  defp egress_row(row) do
    """
    <tr class="v-#{row.verdict}">
      <td><span class="verdict #{row.verdict}">#{row.verdict}</span></td>
      <td>#{escape(row.method || "—")}</td>
      <td class="host">#{escape(row.host || "—")}</td>
      <td class="path">#{escape(row.path || "—")}</td>
      <td>#{escape(row.rule || "—")}#{scheme(row)}</td>
      <td>#{escape(row.status || "—")}#{error(row)}</td>
      <td class="num">#{escape(millis(row.duration_ms))}</td>
    </tr>
    """
  end

  defp scheme(%{scheme: nil}), do: ""
  defp scheme(%{scheme: scheme}), do: ~s( <span class="scheme">#{escape(scheme)}</span>)

  defp error(%{error: nil}), do: ""
  defp error(%{error: error}), do: ~s( <span class="err">#{escape(error)}</span>)

  # The policy, beside the rows the rows name. No values: `Airlock.Policy`
  # holds references and this renders the reference.
  defp policy_details(%{policy: %Policy{} = policy}) do
    """
    <details class="policy"><summary>The policy this run was contained by</summary>
      <p class="note">The box's own egress policy named the broker and nothing else, so every
      host below was reachable only through the proxy.
      Unmatched hosts: <strong>#{escape(policy.unmatched)}</strong>.</p>
      <div class="two">
        <div>
          <h3>Allowed (#{length(policy.allow)})</h3>
          <ul>#{Enum.map_join(policy.allow, "", &"<li><code>#{escape(&1)}</code></li>")}</ul>
        </div>
        <div>
          <h3>Credentials (#{length(policy.credentials)})</h3>
          <ul>#{Enum.map_join(policy.credentials, "", &credential/1)}</ul>
        </div>
      </div>
    </details>
    """
  end

  defp policy_details(_result), do: ""

  defp credential(%Credential{} = credential) do
    from =
      case credential.from do
        {:env, name} -> "$#{name}"
        nil -> "no credential"
      end

    "<li><code>#{escape(credential.host)}</code> " <>
      "<span class=\"scheme\">#{escape(credential.scheme)}</span> " <>
      "<span class=\"from\">#{escape(from)}</span></li>"
  end

  # ── tools ──────────────────────────────────────────────────────────────────

  defp tools_panel(%{transcript: transcript}) do
    calls = Transcript.tool_calls(transcript)
    usage_block(transcript.usage) <> tool_table(calls, transcript) <> permissions(transcript)
  end

  defp tool_table([], _transcript) do
    ~s(<div class="unbuilt"><p>The agent ran no tools.</p></div>)
  end

  defp tool_table(calls, transcript) do
    """
    <p class="note">Every tool call the agent made, in order, threaded to its result on the id
    ACP gives it. <em>Since</em> is milliseconds from the first line of the turn, and
    <em>took</em> is to the call's terminal update — wall clock on this machine, which is
    where the only clock in the exchange is: a <code>session/update</code> carries no time
    of its own.</p>
    <div class="scroll"><table class="egress">
      <thead><tr>
        <th>Status</th><th>Tool</th><th class="num">Since</th><th class="num">Took</th>
      </tr></thead>
      <tbody>#{Enum.map_join(calls, "\n", &tool_row/1)}</tbody>
    </table></div>
    #{thinking_note(transcript)}
    """
  end

  defp tool_row(call) do
    """
    <tr class="v-#{tool_class(call.status)}">
      <td><span class="verdict #{tool_class(call.status)}">#{call.status}</span></td>
      <td>
        <div class="tool-head">
          <span class="tool-name">#{escape(call.name)}</span>
          <span class="tool-summary">#{escape(call.summary)}</span>
        </div>
        #{pre_details("Input", call.input)}#{pre_details("Output", call.output)}
      </td>
      <td class="num">#{escape(millis(call.at_ms))}</td>
      <td class="num">#{escape(millis(call.duration_ms))}</td>
    </tr>
    """
  end

  defp tool_class(:ok), do: "passthrough"
  defp tool_class(:failed), do: "denied"
  defp tool_class(:open), do: "malformed"

  # `Managoat.ACP.Usage` normalises what four runtimes each report
  # somewhere different — gemini does not use the protocol's field at all.
  # A turn that reported none is a turn without a usage, not a zero one,
  # and this says which.
  defp usage_block(nil) do
    ~s|<p class="note">The runtime reported no token usage for this turn. That is a turn | <>
      ~s|without a figure, not a turn that cost nothing.</p>|
  end

  defp usage_block(usage) do
    cells =
      Enum.map_join(Enum.sort(usage), "", fn {key, value} ->
        ~s(<div><dt>#{escape(key)}</dt><dd>#{escape(value)}</dd></div>)
      end)

    ~s(<dl class="meta usage">#{cells}</dl>)
  end

  defp thinking_note(transcript) do
    case Transcript.of_kind(transcript, :thinking) do
      [] -> ""
      blocks -> ~s|<p class="note">#{length(blocks)} thinking block(s) are in the Transcript.</p>|
    end
  end

  defp permissions(transcript) do
    case Transcript.of_kind(transcript, :permission_request) do
      [] ->
        ""

      requests ->
        rows = Enum.map_join(requests, "\n", &block(&1, %{}))

        ~s|<h3>Permission requests (#{length(requests)})</h3>| <>
          ~s|<p class="note">The agent asked, and with nobody attached to answer, | <>
          ~s|Airlock denied. <code>--permissions auto_allow</code> is the other choice, | <>
          ~s|and the caller owns it.</p>| <> rows
    end
  end

  # ── changes ────────────────────────────────────────────────────────────────

  defp changes_panel(%{changes: {:ok, changes}}), do: changed(changes)
  defp changes_panel(%{changes: {:error, reason}}), do: no_changes(reason)

  # A run from before the Changes stage existed, or one whose result was
  # assembled by something that does not collect it. Not the same as a run
  # that changed nothing, and it does not say so.
  defp changes_panel(_result) do
    ~s(<div class="unbuilt"><p>No diff was collected for this run.</p></div>)
  end

  defp changed(%{files: []} = changes) do
    ~s(<div class="unbuilt"><p>The agent left the workspace as it found it: ) <>
      ~s(no file under <code>#{escape(changes.cwd)}</code> changed.</p></div>) <>
      excluded(changes)
  end

  defp changed(changes) do
    """
    <p class="note">Everything that changed under <code>#{escape(changes.cwd)}</code> while the
    agent worked, against the state the box was in when the turn started. The box is per-job and
    was destroyed after, so this is the whole of what it did to disk.</p>
    <div class="scroll"><table class="egress">
      <thead><tr><th>Status</th><th>File</th><th class="num">+</th><th class="num">−</th></tr></thead>
      <tbody>#{Enum.map_join(changes.files, "\n", &file_row/1)}</tbody>
    </table></div>
    #{patch(changes)}
    #{excluded(changes)}
    """
  end

  defp file_row(file) do
    """
    <tr class="v-#{file_class(file.status)}">
      <td><span class="verdict #{file_class(file.status)}">#{escape(file.status)}</span></td>
      <td class="path">#{escape(file.path)}</td>
      <td class="num add">#{escape(lines(file.added))}</td>
      <td class="num del">#{escape(lines(file.removed))}</td>
    </tr>
    """
  end

  defp file_class("added"), do: "passthrough"
  defp file_class("deleted"), do: "denied"
  defp file_class(_status), do: "injected"

  # `nil` is git for a binary file, which is not the same as zero lines.
  defp lines(nil), do: "bin"
  defp lines(0), do: "·"
  defp lines(n), do: to_string(n)

  defp patch(%{diff: ""}), do: ""

  defp patch(changes) do
    note =
      if changes.truncated do
        ~s(<p class="note">The patch was capped and is cut off here. The file list above is not ) <>
          ~s(capped, so nothing that changed is missing from it.</p>)
      else
        ""
      end

    ~s(<details class="policy" open><summary>The patch</summary>) <>
      note <> ~s(<pre class="patch">#{escape(changes.diff)}</pre></details>)
  end

  defp excluded(%{excluded: []}), do: ""

  defp excluded(%{excluded: excluded}) do
    ~s(<p class="note">Not looked at, because a workspace is a home directory and these ) <>
      ~s(change on every turn whatever the prompt was: ) <>
      Enum.map_join(excluded, ", ", &"<code>#{escape(&1)}</code>") <> ".</p>"
  end

  # Every one of these is a fact about the run rather than a bug in the
  # record, so each says which — an empty tab would say the agent changed
  # nothing, and that is a different claim.
  defp no_changes(:git_unavailable) do
    unavailable(
      "git is not installed on this box, so no diff could be taken.",
      "Airlock takes the diff with git: it commits the workspace before the turn and " <>
        "diffs against that commit after. Without git there is no way to say what changed."
    )
  end

  defp no_changes(:workspace_missing) do
    unavailable(
      "The runtime's workspace did not exist on the box.",
      "Nothing was there to diff, which usually means provisioning did not get as far as " <>
        "it reported."
    )
  end

  defp no_changes(:not_a_repository) do
    unavailable(
      "The workspace held no repository when the diff was taken.",
      "The baseline commit is what makes one, so this means it was lost between the " <>
        "baseline and the turn's end."
    )
  end

  defp no_changes({:git_failed, output}) do
    unavailable("git failed while taking the diff.", output)
  end

  defp no_changes({:box, reason}) do
    unavailable("The box could not be reached to take the diff.", inspect(reason))
  end

  defp no_changes(reason) do
    unavailable("No diff could be taken.", inspect(reason))
  end

  defp unavailable(headline, detail) do
    """
    <div class="unbuilt">
      <h2>No diff</h2>
      <p><strong>#{escape(headline)}</strong></p>
      <p class="note">#{escape(detail)}</p>
      <p class="note">This is not the same as an agent that changed nothing; that case says so.</p>
    </div>
    """
  end

  # ── footer ─────────────────────────────────────────────────────────────────

  defp footer(result) do
    """
    <footer>
      <p>Written by <strong>Airlock</strong> #{escape(Airlock.version())} ·
      run #{escape(result.run)} · #{escape(timestamp(Map.get(result, :finished_at)))}</p>
      <p class="note">No credential appears in this file. Airlock's policy objects hold
      references rather than values, and the broker never puts a header or a body in the
      event this record is built from.</p>
    </footer>
    """
  end

  # ── parts ──────────────────────────────────────────────────────────────────

  defp tool_results(%Transcript{} = transcript) do
    transcript
    |> Transcript.of_kind(:tool_result)
    |> Map.new(&{&1[:tool_id], &1})
  end

  @doc "How many rows of each verdict, and the total."
  @spec counts([Egress.row()]) :: map()
  def counts(rows) do
    tallied = Enum.frequencies_by(rows, & &1.verdict)

    %{
      injected: Map.get(tallied, :injected, 0),
      passthrough: Map.get(tallied, :passthrough, 0),
      denied: Map.get(tallied, :denied, 0),
      malformed: Map.get(tallied, :malformed, 0),
      total: length(rows)
    }
  end

  defp empty(message, extra) do
    ~s(<div class="unbuilt"><p>#{escape(message)}</p></div>) <> extra
  end

  defp stderr_details(%{transcript: %Transcript{stderr: stderr}}) when stderr != "" do
    ~s(<details class="stderr"><summary>Adapter stderr</summary><pre>#{escape(stderr)}</pre></details>)
  end

  defp stderr_details(_result), do: ""

  defp provider(result), do: Map.get(result, :provider) || "—"

  defp sealed_to(result), do: Map.get(result, :sealed_to) || "the broker"

  defp timestamp(%DateTime{} = at), do: Calendar.strftime(at, "%Y-%m-%d %H:%M:%S UTC")
  defp timestamp(_at), do: "—"

  defp duration(%{started_at: %DateTime{} = from, finished_at: %DateTime{} = to}) do
    case DateTime.diff(to, from) do
      seconds when seconds < 60 -> "#{seconds}s"
      seconds -> "#{div(seconds, 60)}m #{rem(seconds, 60)}s"
    end
  end

  defp duration(_result), do: "—"

  defp usage(nil), do: "—"
  defp usage(usage), do: Enum.map_join(usage, ", ", fn {key, value} -> "#{key} #{value}" end)

  defp millis(nil), do: "—"
  defp millis(ms) when is_integer(ms), do: "#{ms}ms"
  defp millis(ms), do: "#{Float.round(ms, 1)}ms"

  @doc """
  Escape a value for HTML.

  Every interpolation in this module goes through here. `&` first, or the
  escapes escape each other's ampersands.
  """
  @spec escape(term()) :: String.t()
  def escape(value) do
    value
    |> to_string()
    |> String.replace("&", "&amp;")
    |> String.replace("<", "&lt;")
    |> String.replace(">", "&gt;")
    |> String.replace("\"", "&quot;")
    |> String.replace("'", "&#39;")
  end

  # ── style ──────────────────────────────────────────────────────────────────

  # Inline, because the record is one file. Light and dark from the same
  # tokens: a record is read wherever it is opened, and half of that is a
  # mail client in dark mode.
  defp css do
    """
    :root {
      --bg: #fbfbfa; --card: #fff; --ink: #1a1a19; --dim: #6b6b66; --line: #e2e2dd;
      --ok: #1c7c4a; --warn: #8a6100; --bad: #a4262c; --accent: #2c5aa0;
      --code: #f4f4f1;
    }
    @media (prefers-color-scheme: dark) {
      :root {
        --bg: #16171a; --card: #1d1e22; --ink: #e6e6e3; --dim: #9a9a94; --line: #303238;
        --ok: #63c48c; --warn: #d3a441; --bad: #f08a8f; --accent: #86aee8;
        --code: #232429;
      }
    }
    * { box-sizing: border-box; }
    body {
      margin: 0; background: var(--bg); color: var(--ink);
      font: 15px/1.55 ui-sans-serif, -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    }
    header, .tabs, footer { max-width: 68rem; margin: 0 auto; padding: 0 1.25rem; }
    header { padding-top: 2rem; }
    .title { display: flex; align-items: baseline; gap: .75rem; flex-wrap: wrap; }
    h1 { font-size: 1.35rem; margin: 0; letter-spacing: -.01em; }
    h2 { font-size: 1.05rem; margin: 0 0 .5rem; }
    h3 { font-size: .8rem; margin: 0 0 .4rem; text-transform: uppercase;
         letter-spacing: .06em; color: var(--dim); }
    code, pre, .num, .run { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
    .run { color: var(--dim); font-size: .85rem; }
    .claim { margin: 1rem 0; padding: .8rem 1rem; border-radius: 8px; border: 1px solid var(--line);
             background: var(--card); font-size: .95rem; }
    .claim.sealed { border-left: 3px solid var(--ok); }
    .claim.unsealed { border-left: 3px solid var(--bad); }
    dl.meta { display: grid; grid-template-columns: repeat(auto-fit, minmax(11rem, 1fr));
              gap: .1rem 1.5rem; margin: 1rem 0; }
    dl.meta div { padding: .35rem 0; border-top: 1px solid var(--line); }
    dt { font-size: .72rem; text-transform: uppercase; letter-spacing: .06em; color: var(--dim); }
    dd { margin: .1rem 0 0; font-size: .9rem; word-break: break-word; }
    .prompt { margin: 1rem 0 0; }
    .prompt .label { font-size: .72rem; text-transform: uppercase; letter-spacing: .06em;
                     color: var(--dim); }
    .prompt pre { margin: .3rem 0 0; }
    pre { white-space: pre-wrap; word-break: break-word; margin: .4rem 0 0;
          background: var(--code); padding: .6rem .75rem; border-radius: 6px;
          font-size: .82rem; overflow-x: auto; }
    .note { color: var(--dim); font-size: .85rem; }

    .tabs { margin-top: 1.75rem; padding-bottom: 3rem; }
    .tabs > input { position: absolute; opacity: 0; pointer-events: none; }
    nav { display: flex; gap: .25rem; border-bottom: 1px solid var(--line); flex-wrap: wrap; }
    nav label { padding: .5rem .85rem; cursor: pointer; font-size: .9rem; color: var(--dim);
                border-bottom: 2px solid transparent; margin-bottom: -1px; user-select: none; }
    nav label:hover { color: var(--ink); }
    .count { display: inline-block; margin-left: .4rem; padding: 0 .35rem; border-radius: 999px;
             background: var(--code); font-size: .72rem; color: var(--dim); }
    .panel { display: none; padding-top: 1.25rem; }
    #tab-transcript:checked ~ #panel-transcript,
    #tab-egress:checked ~ #panel-egress,
    #tab-tools:checked ~ #panel-tools,
    #tab-changes:checked ~ #panel-changes { display: block; }
    #tab-transcript:checked ~ nav label[for="tab-transcript"],
    #tab-egress:checked ~ nav label[for="tab-egress"],
    #tab-tools:checked ~ nav label[for="tab-tools"],
    #tab-changes:checked ~ nav label[for="tab-changes"] {
      color: var(--ink); border-bottom-color: var(--accent); font-weight: 600;
    }

    .msg { margin: 0 0 .9rem; }
    .msg.agent pre { background: var(--card); border: 1px solid var(--line); font-size: .88rem;
                     font-family: inherit; }
    .msg.thinking summary, details summary { cursor: pointer; font-size: .82rem; color: var(--dim); }
    .tool { border: 1px solid var(--line); border-radius: 8px; background: var(--card);
            padding: .7rem .85rem; margin: 0 0 .9rem; }
    .tool.failed { border-left: 3px solid var(--bad); }
    .tool.permission { border-left: 3px solid var(--warn); }
    .tool-head { display: flex; align-items: baseline; gap: .6rem; flex-wrap: wrap; }
    .tool-name { font-weight: 600; font-size: .9rem; }
    .tool-summary { color: var(--dim); font-size: .82rem; word-break: break-all; }
    .status { margin-left: auto; font-size: .72rem; text-transform: uppercase;
              letter-spacing: .05em; }
    .status.ok { color: var(--ok); } .status.denied { color: var(--bad); }
    .status.open { color: var(--dim); }

    .scroll { overflow-x: auto; border: 1px solid var(--line); border-radius: 8px;
              background: var(--card); }
    table.egress { border-collapse: collapse; width: 100%; font-size: .84rem; }
    table.egress th { text-align: left; font-size: .7rem; text-transform: uppercase;
                      letter-spacing: .06em; color: var(--dim); font-weight: 600;
                      padding: .55rem .7rem; border-bottom: 1px solid var(--line); }
    table.egress td { padding: .45rem .7rem; border-bottom: 1px solid var(--line);
                      vertical-align: top; }
    table.egress tr:last-child td { border-bottom: 0; }
    td.host, td.path { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
                       font-size: .8rem; word-break: break-all; }
    td.num, th.num { text-align: right; white-space: nowrap; }
    .verdict { font-size: .72rem; text-transform: uppercase; letter-spacing: .05em;
               font-weight: 600; }
    .verdict.injected { color: var(--accent); }
    .verdict.passthrough { color: var(--ok); }
    .verdict.denied { color: var(--bad); }
    .verdict.malformed { color: var(--warn); }
    dl.usage { margin: 0 0 1.25rem; }
    td.add { color: var(--ok); } td.del { color: var(--bad); }
    pre.patch { font-size: .78rem; white-space: pre; overflow-x: auto; max-height: 40rem;
                overflow-y: auto; }
    tr.v-denied { background: color-mix(in srgb, var(--bad) 7%, transparent); }
    .scheme, .from, .err { font-size: .74rem; color: var(--dim); }
    .err { color: var(--bad); }

    details.policy, details.stderr { margin-top: 1.25rem; border: 1px solid var(--line);
                                     border-radius: 8px; padding: .7rem .85rem;
                                     background: var(--card); }
    .two { display: grid; grid-template-columns: repeat(auto-fit, minmax(15rem, 1fr));
           gap: 1.25rem; margin-top: .75rem; }
    .two ul { margin: 0; padding-left: 1.1rem; font-size: .85rem; }
    .two li { margin-bottom: .2rem; }
    .unbuilt { border: 1px dashed var(--line); border-radius: 8px; padding: 1.25rem;
               background: var(--card); }
    .unbuilt p { margin: .35rem 0; }
    footer { border-top: 1px solid var(--line); padding-top: 1rem; padding-bottom: 2.5rem;
             font-size: .8rem; color: var(--dim); }
    footer p { margin: .3rem 0; }
    """
  end
end
