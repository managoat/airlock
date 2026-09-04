# M2 notes — what building the record found

Written 2026-09-04, against the libraries as actually pinned. Same rule as
`NOTES-M0.md`: findings that change the plan go here rather than being
folded silently into `PLAN.md`, because some of them are decisions rather
than corrections.

M2 is the record — `PLAN.md` calls it the thing that turns a utility into a
product, and the README's claim is that you can *hand someone* the record.
M0 left it as a terminal table.

## Contents

1. [The Tools tab cannot come from `Managoat.ACP.Tracer`](#1-the-tools-tab-cannot-come-from-managoatacptracer)
2. [`Fountain.SandboxFiles` was not extracted, and the diff is not `git diff`](#2-fountainsandboxfiles-was-not-extracted-and-the-diff-is-not-git-diff)
3. [Smaller findings](#3-smaller-findings)
4. [Known gaps](#4-known-gaps)

---

## 1. The Tools tab cannot come from `Managoat.ACP.Tracer`

`PLAN.md`'s Tools tab: "spans from `Managoat.ACP.Tracer`, plus normalised
token usage from `Managoat.ACP.Usage`". The second half is right and is
what shipped. The first half cannot work here, and the way it fails is the
expensive kind: it produces an empty tab rather than an error.

`Tracer` emits **OpenTelemetry** spans. Its own moduledoc says so, and says
what follows:

> The OpenTelemetry *API* is the only dependency: with no SDK started every
> span call is a no-op.

Airlock's dependency tree holds `opentelemetry_api` (transitively, through
`managoat_acp`) and **no SDK**. So wiring `Tracer` into `Airlock.Run` would
compile, run, report nothing, and leave the Tools tab permanently blank —
and a blank tab reads as an agent that used no tools.

Three ways out were considered:

| | |
|---|---|
| **a. Add an OTel SDK and an in-memory exporter** | Start `opentelemetry`, export spans to a collector process, read them back at the end of the turn. It works, and it is a long way round: it adds two dependencies to an escript so a module can write spans this program then reads back, when the same data is already in `Airlock.Transcript` in order. It also does not carry usage — `Tracer` drops it deliberately, and says so. |
| **b. Derive the calls from the blocks — chosen** | `Managoat.ACP.Blocks` threads a `tool_call` to its `tool_call_update` on `toolCallId` *by construction*, which is exactly what `Tracer` keys on. The one thing missing is time, and the process reading the lines is the only place that exists. `Airlock.Transcript.add_line/2` stamps each block with `at_ms`, and `tool_calls/1` follows the thread. No new dependency, and the durations are real wall clock. |
| **c. Ship the tab without timings** | Cheapest, and it throws away the most interesting column. |

**Chosen: (b).** `Tracer` is not wrong and is not replaced — it is for a
host with dashboards, and Airlock is a file. A future Airlock that grows an
OTel story should call `Tracer` *as well*; it would not replace this.

Worth stating plainly, because it is the kind of thing that gets
rediscovered: `PLAN.md`'s line was written from reading the library list,
not from running it. The tell was in the moduledoc all along.

### The one thing (b) does not give

`Tracer` counts `text_bytes` and `thinking_bytes` per turn, which the
blocks path could compute but does not, because nothing has wanted it.
Not built, and not claimed.

## 2. `Fountain.SandboxFiles` was not extracted, and the diff is not `git diff`

`PLAN.md`: "**Changes** — the diff. This is where `Fountain.SandboxFiles`
gets extracted into a library; not before." Two things came out of doing
it, and they are separate decisions.

### The question does not transfer, so the code mostly does not either

`SandboxFiles` is 479 lines doing three operations — list, read, `git
diff` — and its shape is right: fixed scripts over
`Managoat.Sandbox.exec/4`, positional parameters so a filename is never
interpolated into a script, base64 out so bytes survive whatever an
adapter streams stdout over, path confinement, and redaction on the way
past. `Airlock.Changes` keeps all of that.

What does not transfer is what it asks. Fountain's sandboxes are
long-lived and its conversations clone a repository, so "what is
uncommitted right now" is the whole question. **Airlock's box is per-job
and starts with no repository at all**, so `git diff` on it answers
nothing — an agent's output is mostly *new files*, and `git diff` shows
none of them.

`PLAN.md`'s own settled question 4 says what to do instead, in the
sentence that justifies the per-job box: *a run's diff is relative to a
known starting state rather than to whatever the last run left behind.* So
Airlock **makes** the starting state — `git init` in the workspace if
there is none, commit what provisioning put there — and diffs against it
after the turn. `Airlock.Changes.baseline/3` and `since/3`, bracketing the
turn, both before `Box.destroy/1`.

That bracket is the piece Fountain does not have and would not want.

### Not extracted, deliberately

Being needed is not the whole test for a library; a second consumer and a
settled API are the rest. This has one consumer, one of the three
operations, and a step Fountain has no use for. Extracting now would
freeze a shape before the only product with a policy has ever run it,
which is the same reasoning that settled `provision.ex` in `PLAN.md`'s
question 1 — and that one has held up.

**Revisit when** a second consumer wants the *pair*: a known starting
state and a diff against it. The thing to extract then is the bracket, not
the diff.

### What the diff leaves out, and why it is printed

A workspace is a **home directory** for claude and codex —
`Managoat.Runtimes.Layout` puts `cwd` at `/home/sprite` for both — so it
holds the agent harness's own bookkeeping: session logs, npm's `_logs`,
caches. Every one of those changes on every turn whatever the prompt was,
and left in they bury the agent's work.

`Airlock.Changes.excludes/0` is the list, passed to git as
`:(exclude,glob)**/<name>/**` pathspecs, and the record **prints it in
the tab**. Taken out silently, the record would claim a completeness it
does not have.

### The one secret on the box is the session token

The box holds placeholders, not credentials — so there is almost nothing
to redact from a diff, which is the product working. The exception is the
**proxy URL**: it carries the broker's session token, which is the
authority to use every credential the policy names, and it is in the
turn's environment. An agent that wrote its environment to a file would
put it in the diff. `Airlock.Run` passes the token to `since/3`'s
`:redact`.

Placeholders are deliberately not redacted. A placeholder in the diff is
evidence the containment worked.

### `Airlock.Test.LocalBox`, and why a fake was not enough

`Managoat.Sandbox.Fake` answers every unrecognised argv, and
`Airlock.Test.FakeBox` makes that exit 0 with empty output. Three bash
scripts and two `-z` parsers all pass against that, and every one of them
can still be wrong: a pathspec that excludes nothing, a record shape that
is not what git emits, a pipeline whose exit status is `base64`'s rather
than `git`'s.

So `test/support/local_box.ex` runs the argv with `System.cmd/3` against a
temporary directory, and `changes_test.exs` asserts on the git that is
installed rather than on a memory of its output. It is test support and
not a sandbox — there is no isolation in it whatsoever.

Related, and worth keeping: `from_baseline_exec({:ok, "", 0})` is an
**error**, not an empty result. A box that answers every command with exit
0 must not look like an agent that changed nothing.

## 3. Smaller findings

- **A run of `:text` blocks is a message; every `:text` block in a turn is
  not.** `Managoat.ACP.Blocks` says a renderer concatenates adjacent
  chunks, and M0 read that as "join them all". A tool call between two
  runs of text ends the first message and starts the second, so joining
  across it produced `...I have fetched it now.You denied...` in every M0
  record. `Airlock.Transcript.messages/1` groups by adjacency;
  `text/1` joins the groups with a blank line.
- **A tool call with no terminal update is `:open`, not `:failed`.** The
  turn ended or the adapter died with the call in flight. Calling that a
  failure invents an outcome the agent never reported, and the record is
  evidence.
- **The record is written from memory, so it cannot ask the box
  anything.** A box is per-job and `Airlock.Run` destroys it on both the
  happy and the error path, so anything the record wants off the box has
  to be collected *before* `Box.destroy/1`. That is why the Changes tab is
  a stage in the run rather than a step in the writer.
- **The baseline commits into a repository that is already there**, if
  ever there is one. Airlock never clones, so today the workspace has no
  repository until `baseline/3` makes one — but an M3 policy with a
  `repo:` key would change that, and the baseline would then add a commit
  to the user's history. Worth deciding before that key exists.

## 4. Known gaps

Recorded here rather than in a docstring, per `CLAUDE.md`'s rule about
never describing unbuilt behaviour as existing.

- **The diff is not taken when the turn fails.** It could be — the box is
  still there — but a failed run writes no record at all, so there is
  nowhere to put it. The two gaps are one gap and this is the smaller
  half.
- **A failed run writes no record.** `Airlock.Run.start/1` returns
  `{:error, reason}` and the egress rows collected up to that point are
  dropped. That is backwards for a containment product: a run that failed
  *because* the agent was refused something is exactly the run whose rows
  matter. Not fixed here because it changes `Run`'s return shape, which is
  M1's business as much as M2's.
- **Provisioning egress is still not in the record**, by design.
  `NOTES-M0.md` §9 has the reasoning: the proxy environment is applied to
  the turn, not to provisioning, so a policy does not have to name the npm
  registry to run an agent that never touches npm.
