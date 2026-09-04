defmodule Airlock.RecordTest do
  @moduledoc """
  M2 step 1: the record as a file someone can be handed.

  Three things are worth pinning here and the rest is drawing:

    * **it is self-contained** — no stylesheet, script or font fetched from
      anywhere, because a record that phones home is not a record you can
      hand to someone on a different network in six months;
    * **everything is escaped** — a transcript is an agent's output and a
      hostname is whatever the agent tried to reach, and the record of a
      run that went wrong is exactly the one somebody opens;
    * **no credential and no session token appears**, which is the claim
      the footer makes in words.
  """

  use ExUnit.Case, async: true

  alias Airlock.Egress
  alias Airlock.Policy
  alias Airlock.Record
  alias Airlock.Transcript

  @policy_yaml """
  allow:
    - api.stripe.com
    - example.com

  credentials:
    - host: api.stripe.com
      name: stripe
      scheme: bearer
      from: env:STRIPE_KEY

  unmatched: deny
  """

  setup do
    {:ok, policy} = Policy.parse(@policy_yaml)
    %{policy: policy}
  end

  describe "the file" do
    test "is written where it is asked for, and named after the run by default", %{policy: policy} do
      path = Path.join(System.tmp_dir!(), "record-#{System.unique_integer([:positive])}.html")
      on_exit(fn -> File.rm(path) end)

      assert {:ok, ^path} = Record.write(result(policy), path: path)
      assert File.read!(path) =~ "Airlock record"

      assert Record.default_path(%{run: "abc123"}) == "airlock-abc123.html"
    end

    test "says so rather than failing the run when it cannot be written", %{policy: policy} do
      path = Path.join(System.tmp_dir!(), "no-such-dir-#{System.unique_integer()}/r.html")

      assert {:error, {:record_unwritable, ^path, :enoent}} =
               Record.write(result(policy), path: path)
    end

    test "fetches nothing: no script, no stylesheet, no font, no CDN", %{policy: policy} do
      html = Record.html(result(policy))

      # The one file is the whole record: nothing here can pull a byte off
      # a network. `<script` is checked twice over, because it is also the
      # only way an escaping mistake below becomes execution.
      for tag <- ~w(<script <link <iframe <object <embed src= @import) do
        refute html =~ tag
      end

      # The style block is inline and stays inline: `url()` is how a
      # stylesheet fetches a font or an image, and `@import` how it fetches
      # another stylesheet.
      [_, style] = String.split(html, "<style>", parts: 2)
      [style, _] = String.split(style, "</style>", parts: 2)
      refute style =~ "url("
      refute style =~ "//"
    end

    test "switches tabs with CSS and not JavaScript", %{policy: policy} do
      html = Record.html(result(policy))

      # Four radios and a sibling selector. The page works with scripting
      # off and in whatever a reviewer's mail client renders.
      for tab <- ~w(transcript egress tools changes) do
        assert html =~ ~s(id="tab-#{tab}")
        assert html =~ "#tab-#{tab}:checked ~ #panel-#{tab}"
      end
    end
  end

  describe "escaping" do
    test "agent output is text, never markup", %{policy: policy} do
      transcript =
        Transcript.new()
        |> add_text(~s|<script>alert("xss")</script> & <img src=x onerror=1>|)

      html = Record.html(result(policy, transcript: transcript))

      refute html =~ "<script>alert"
      refute html =~ "<img src=x"
      assert html =~ "&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt; &amp;"
    end

    test "a hostname the agent chose is escaped too", %{policy: policy} do
      # The host on an egress row is whatever the agent tried to reach,
      # which under `unmatched: deny` is precisely the untrusted half.
      rows = [row(host: ~s|evil"><script>x</script>.example|, verdict: :denied)]

      html = Record.html(result(policy, egress: rows))

      refute html =~ "<script>x</script>"
      assert html =~ "evil&quot;&gt;&lt;script&gt;"
    end

    test "escapes the ampersand first, so the escapes do not escape each other" do
      assert Record.escape("<&>") == "&lt;&amp;&gt;"
      refute Record.escape("&lt;") == "&amp;amp;lt;"
      assert Record.escape("&lt;") == "&amp;lt;"
    end
  end

  describe "what it never contains" do
    test "no credential value and no session token", %{policy: policy} do
      # There is nowhere for either to come from — a policy holds
      # `{:env, "STRIPE_KEY"}` and never a value, and the record is built
      # from rows that carry no headers — so this asserts the structure
      # rather than a filter.
      html = Record.html(result(policy))

      assert html =~ "$STRIPE_KEY"
      refute html =~ "sk_test"
      refute html =~ "Proxy-Authorization"
      refute html =~ "proxy_url"
    end
  end

  describe "the claim" do
    test "a sealed run says what the box could reach", %{policy: policy} do
      html = Record.html(result(policy, sealed?: true, sealed_to: "4.tcp.ngrok.io"))

      assert html =~ "The box reached 4.tcp.ngrok.io and nothing else"
      assert html =~ "1 carried a credential the box never held"
      assert html =~ "1 were refused"
    end

    test "an unsealed run says the opposite, in as many words", %{policy: policy} do
      # A reader who does not see a containment claim concludes there was
      # one. The absence of a line is not a disclaimer.
      html = Record.html(result(policy, sealed?: false))

      assert html =~ "This box was not sealed"
      assert html =~ "are not below"
    end
  end

  describe "the tabs" do
    test "the egress table names the verdict and the rule that decided it", %{policy: policy} do
      html = Record.html(result(policy))

      assert html =~ ~s(<span class="verdict injected">injected</span>)
      assert html =~ ~s(<span class="verdict denied">denied</span>)
      assert html =~ "stripe"
      assert html =~ "pastebin.com"
    end

    test "the policy travels with the rows that name its rules", %{policy: policy} do
      html = Record.html(result(policy))

      assert html =~ "The policy this run was contained by"
      assert html =~ "api.stripe.com"
      assert html =~ "Unmatched hosts: <strong>deny</strong>"
    end

    test "a run with no diff collected says that, not that nothing changed", %{policy: policy} do
      # An empty tab and an uncollected one look identical, and only one of
      # them is a claim about the agent. This is the uncollected case: a
      # result assembled without the Changes stage.
      changes = policy |> result() |> Record.html() |> panel("changes")

      assert changes =~ "No diff was collected"
      refute changes =~ "left the workspace as it found it"
    end

    test "a failed diff names why, and says it is not an agent that changed nothing", %{
      policy: policy
    } do
      changes =
        policy
        |> result(changes: {:error, :git_unavailable})
        |> Record.html()
        |> panel("changes")

      assert changes =~ "git is not installed on this box"
      assert changes =~ "not the same as an agent that changed nothing"
    end

    test "the changes tab lists the files, the counts and the patch", %{policy: policy} do
      changes =
        policy
        |> result(
          changes:
            {:ok,
             %{
               cwd: "/home/sprite",
               files: [
                 %{path: "answer.txt", status: "added", added: 3, removed: 0},
                 %{path: "old.txt", status: "deleted", added: 0, removed: 9},
                 %{path: "logo.png", status: "modified", added: nil, removed: nil}
               ],
               diff: "diff --git a/answer.txt b/answer.txt\n+42\n",
               truncated: false,
               excluded: ["node_modules", ".claude"]
             }}
        )
        |> Record.html()
        |> panel("changes")

      assert changes =~ "answer.txt"
      assert changes =~ ~s(<span class="verdict passthrough">added</span>)
      assert changes =~ ~s(<span class="verdict denied">deleted</span>)
      # `nil` is git for a binary file, which is not zero lines.
      assert changes =~ "bin"
      assert changes =~ "diff --git"
      assert changes =~ "node_modules"
    end

    test "a run that changed nothing says so, and still says what it did not look at", %{
      policy: policy
    } do
      changes =
        policy
        |> result(
          changes:
            {:ok,
             %{
               cwd: "/home/sprite",
               files: [],
               diff: "",
               truncated: false,
               excluded: ["node_modules"]
             }}
        )
        |> Record.html()
        |> panel("changes")

      assert changes =~ "left the workspace as it found it"
      assert changes =~ "node_modules"
    end

    test "a tool call carries its result and its status", %{policy: policy} do
      transcript =
        Transcript.new()
        |> add(%{
          "sessionUpdate" => "tool_call",
          "toolCallId" => "t1",
          "title" => "curl example.com",
          "rawInput" => %{"url" => "http://example.com"}
        })
        |> add(%{
          "sessionUpdate" => "tool_call_update",
          "toolCallId" => "t1",
          "status" => "failed",
          "content" => [
            %{"type" => "content", "content" => %{"type" => "text", "text" => "boom"}}
          ]
        })

      html = Record.html(result(policy, transcript: transcript))

      assert html =~ "curl example.com"
      assert html =~ ~s(<span class="status denied">failed</span>)
      assert html =~ "boom"

      # In the transcript the result is rendered inside the call it belongs
      # to, not again as a loose block after it. (It appears a second time
      # in the Tools panel, which is a different tab and the point of it.)
      transcript_panel = panel(html, "transcript")
      assert transcript_panel |> String.split("boom") |> length() == 2
    end

    test "the tools panel counts the calls, times them, and names the tokens", %{policy: policy} do
      transcript =
        Transcript.new()
        |> add(%{"sessionUpdate" => "tool_call", "toolCallId" => "t1", "title" => "read"})
        |> add(%{
          "sessionUpdate" => "tool_call_update",
          "toolCallId" => "t1",
          "status" => "completed"
        })
        |> Transcript.finish("end_turn", %{"input" => 12, "output" => 3})

      html = Record.html(result(policy, transcript: transcript))
      tools = panel(html, "tools")

      assert tools =~ "read"
      assert tools =~ ~s(<span class="verdict passthrough">ok</span>)
      assert tools =~ "input"
      assert html =~ ~s(<span class="count">1</span>)
    end

    test "a tool call with no terminal update is open, not failed", %{policy: policy} do
      # A call that never reported an outcome did not fail. Saying it did
      # invents one, and the record is evidence.
      transcript =
        Transcript.new()
        |> add(%{"sessionUpdate" => "tool_call", "toolCallId" => "t1", "title" => "read"})

      tools = policy |> result(transcript: transcript) |> Record.html() |> panel("tools")

      assert tools =~ ~s(<span class="verdict malformed">open</span>)
      refute tools =~ "failed"
    end

    test "a turn that reported no usage says so rather than showing zero", %{policy: policy} do
      tools = policy |> result() |> Record.html() |> panel("tools")

      assert tools =~ "reported no token usage"
      assert tools =~ "not a turn that cost nothing"
    end
  end

  describe "counts/1" do
    test "tallies every verdict, including the ones that are zero" do
      rows = [row(verdict: :denied), row(verdict: :denied), row(verdict: :injected)]

      assert Record.counts(rows) == %{
               injected: 1,
               passthrough: 0,
               denied: 2,
               malformed: 0,
               total: 3
             }
    end
  end

  # ── helpers ────────────────────────────────────────────────────────────────

  # One tab's panel. The panels are siblings, so the next `<section` ends it.
  defp panel(html, id) do
    [_, rest] = String.split(html, ~s(<section class="panel" id="panel-#{id}">), parts: 2)
    rest |> String.split("<section class=\"panel\"", parts: 2) |> List.first()
  end

  defp result(policy, overrides \\ []) do
    base = %{
      run: "0123456789abcdef",
      transcript: add_text(Transcript.new(), "I fetched it."),
      egress: [
        row(host: "api.stripe.com", path: "/v1/charges", rule: "stripe", verdict: :injected),
        row(host: "pastebin.com", path: "/raw/x", rule: nil, verdict: :denied, status: 403)
      ],
      box: "airlock-deadbeef",
      sealed?: true,
      provider: :sprites,
      runtime: "claude",
      prompt: "fetch two urls",
      policy: policy,
      policy_path: "policy.yaml",
      sealed_to: "broker.example",
      started_at: ~U[2026-09-03 12:00:00Z],
      finished_at: ~U[2026-09-03 12:02:30Z]
    }

    Enum.into(overrides, base)
  end

  @spec row(keyword()) :: Egress.row()
  defp row(overrides) do
    Enum.into(overrides, %{
      method: "GET",
      host: "example.com",
      path: "/",
      verdict: :passthrough,
      rule: "allow:example.com",
      scheme: :passthrough,
      status: 200,
      error: nil,
      duration_ms: 12.5
    })
  end

  defp add_text(transcript, text) do
    add(transcript, %{
      "sessionUpdate" => "agent_message_chunk",
      "content" => %{"type" => "text", "text" => text}
    })
  end

  defp add(transcript, update) do
    line =
      Jason.encode!(%{
        "jsonrpc" => "2.0",
        "method" => "session/update",
        "params" => %{"sessionId" => "s1", "update" => update}
      })

    Transcript.add_line(transcript, line)
  end
end
