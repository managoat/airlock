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
2. [Smaller findings](#2-smaller-findings)
3. [Known gaps](#3-known-gaps)

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

## 2. Smaller findings

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

## 3. Known gaps

Recorded here rather than in a docstring, per `CLAUDE.md`'s rule about
never describing unbuilt behaviour as existing.

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
