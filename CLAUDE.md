# CLAUDE.md — Airlock

This file is read by Claude Code (and other AI coding tools) at session start.
It is the brief. Keep it accurate; stale guidance misleads every session after
it.

## What Airlock is

Airlock runs a coding agent on a machine you chose, with credentials that
machine never holds, and hands you a record of everything the agent did.

You give it a **policy** — the complete list of hosts a job may reach and which
credential goes to which host. It provisions a **box**, brings up one of four
coding agents on it, and lets the agent work. The agent sees placeholders where
your keys should be; the real credentials are attached at a proxy that is the
box's only way out. Every outbound request is logged with the verdict the proxy
reached and the rule that decided it. You can detach and reattach from anywhere;
the job does not need you present.

The thesis, in one line: **this is a containment product that happens to run
agents, not a parallelism product with security features.**

That framing came from reading the nine `managoat_*` libraries for what they
make cheap rather than for parity with any existing tool. Three of the four
things the stack is unusually good at are about boundary and evidence — the
box's egress, the credential broker, the record. Only one is about the agent
itself, and that one is interchangeable by design.

## Status

**M0 steps 1–3 are built; nothing else is.** As of 2026-09-03 this
repository holds this brief, `PLAN.md`, `NOTES-M0.md` and an Elixir
project: the policy file parsed, validated and compiled onto both layers;
the broker started with a per-run session; the egress log as a telemetry
handler; and the `Runner.Host` and WebSocket endpoint a local box would be
presented through. Provisioning, the runtime, the seal, the turn and the
record-as-a-file (M0 steps 4–9) are **not built**, which is why
`Airlock.CLI` has no `run` command.

**Read `NOTES-M0.md` before planning further work.** Building steps 1–3
found two blockers that reorder M0 — the local box cannot be sealed, and
there is no runner daemon — and corrected several facts in this file. A
sibling product, goatherd, shares the substrate and has two findings worth
carrying over; see the next section.

Carry this rule over from Fountain, it is load-bearing: **never describe
unbuilt behaviour as existing.** If a document, docstring or README describes
something not yet in code, say so explicitly (`Not yet built`), and delete the
caveat in the same PR that builds it. A 2026-07 audit in Fountain found three
mechanisms asserted as implemented that did not exist, and everyone reading the
docs concluded the system was metered and gated when it was neither.

## Its sibling: goatherd

`managoat/goatherd` (private, `~/dev/managoat/goatherd`) is 2,042 lines of
Elixir built on 2026-09-03: an escript that runs coding agents in remote Sprites
sandboxes from a terminal, with no server, no account, no database and no web
UI. It uses `managoat_sandbox`, `managoat_runtimes` and `managoat_acp`.

**Airlock is not goatherd phase two, and the code overlap is small.** The two
were reached from opposite directions — goatherd by deleting Fountain's server
until only a terminal was left, Airlock by asking what the libraries make cheap
— and they converge only on the substrate, which is the three libraries doing
exactly the job they were extracted for. Read goatherd for its findings; do not
plan to fork it.

Where the 2,042 lines actually go, and what transfers:

| goatherd module | Lines | To Airlock |
|---|---|---|
| `driver.ex` | 551 | **Its reasoning does not transfer.** Its moduledoc argues the driver should be the CLI process rather than a GenServer, because there is one turn per invocation and the terminal is its only consumer. Airlock has a second consumer (the record), a persisted artefact, and a broker session whose lifetime brackets the turn. Different answer. |
| `cli.ex` | 453 | Airlock is a CLI too (settled question 3), so this is worth reading for shape — though its commands are goatherd's, not Airlock's. |
| `provision.ex` | 227 | **The genuinely shared piece.** Get a box up with a runtime on it, ready for ACP. Airlock needs the same thing plus a network policy and proxy environment. |
| `config.ex` | 183 | A pattern for the policy parser, not code. Different schema. |
| `auth.ex` | 167 | Different job — Airlock's whole point is that credentials go to the broker, not to the box. |
| `render.ex` | 168 | Terminal rendering. Airlock renders a page. |
| `state.ex` + `runs.ex` | 185 | The *insight* transfers; the code is thin enough to rewrite. |
| `keychain.ex` | 65 | Reusable as-is if Airlock reads macOS keychain credentials. |

So roughly 300 of 2,042 lines are shared surface. What genuinely transfers is
two findings — and a question, since settled, about whether provisioning should
have been shared at all.

**Finding 1 — durability is the sandbox's, not the client's.** The adapter is
spawned `detachable: true`, so it keeps running in the sandbox when the driving
process exits; resuming means opening a fresh connection and resuming the
agent's own session. A pointer file holding sandbox name, session id and prompt
id is sufficient durable state. This is why goatherd needed no database, and it
is why an early sketch of this plan — ~600 lines of supervision plus SQLite —
was wrong. Airlock still wants storage for the *record*, but not for the
session.

**Finding 2 — the `function_exported?` trap**, in the escript section below.

**Settled — `provision.ex` is not the tenth library.** Decided 2026-09-03; the
reasoning and the revisit condition are in `PLAN.md`'s settled questions. Short
version: about 50 of its 227 lines transfer, its env precedence runs the
opposite direction to Airlock's, and goatherd never applies a network policy or
installs skills — so the ordering it calls hard-won is missing both the
terminal seal and the skills-before-lockdown constraint Airlock is built
around. Airlock writes its own. The one thing that did go upstream is a safe
dispatcher for `managoat_runtimes`' four optional callbacks, shipped in 0.3.0;
see the `function_exported?` trap below.

### Why goatherd could not have been Airlock

Not a matter of scope or sequencing. goatherd is a laptop escript, and a laptop
is not reachable from a cloud sandbox's network — so it structurally cannot host
the broker. That is a fork in the road, not a phase boundary, and it is the same
constraint that shapes Airlock's architecture below.

## The constraint that shapes the architecture

**The broker is a listener the sandbox dials out to, so the sandbox has to be
able to reach it.** That single fact decides more about Airlock's deployment
than anything else:

- With a **cloud** sandbox (Sprites, E2B, Daytona), the broker needs an address
  reachable from that provider's network — a deployed server, or a tunnel. This
  is precisely why goatherd, which is a laptop escript, could not have the
  broker.
- With a **local box** via `managoat_runner`, the broker is on the same machine
  the box is. Trivially reachable, no public address, no hosting, no tunnel.

So `managoat_runner` is not a late nice-to-have; it is the **cheapest path to a
working Airlock**, and the plan orders it accordingly. The cloud-sandbox path is
the one that needs a deployment story, not the other way round.

## What Airlock is not

This list is the product boundary. It exists because every one of these is a
plausible next feature that would turn Airlock into a different, worse product.
If you find yourself building one, stop and re-read this section.

- **Not multi-tenant.** No accounts, no roles, no sign-in, no hosted tier. One
  human, their tokens, their box. The moment a user wants teams or hosting,
  what they want is Fountain — and the export path should say so.
- **Not a place agents live.** Fountain's teammates have continuity, schedules,
  an inbox and a phone number. Airlock runs a job, keeps the box if you asked
  it to, and gives you the record.
- **Not a chat UI.** The interesting surfaces are the policy going in and the
  record coming out. The transcript is one tab of four.
- **Not Conductor.** No git worktrees, no branch-per-task board, no pull
  request flow, no racing several attempts at one task while you watch. That
  framing was considered first and rejected: it needs a worktree layer, a git
  host integration and a fast cold start, and it fights the stack on all three.
- **Not optimised to start fast.** It is optimised to be safe to leave. Those
  trade against each other and the stack already picked. A three-minute clone
  does not matter to a job you detached from.

## The four nouns

| Noun | What it is |
|---|---|
| **Box** | A machine. Provider, image, lifetime, disk. Kept across jobs or thrown away after one. |
| **Policy** | What a box may reach and with which credentials: the egress allow list plus the broker rules. The thing a user actually authors, versions and reuses. Lives as a file you check in. |
| **Session** | An agent at work on a box under a policy. Detachable, resumable, survives the client going away — because the box holds the durable state, not the client. |
| **Record** | What happened: transcript, egress log, tool spans, token usage, and the diff. One page, exportable, the thing you hand someone. |

`Policy` and `Record` are first class because the libraries already produce
them, and because they are the two things goatherd does not have. Anything that
makes them second-class is going the wrong way.

## Where the work comes from

Nine libraries, all on hex, all Apache-2.0, all extracted from Fountain under
its ADR 0037 and graduated in #1345 / #1368. Source lives at
`github.com/managoat/managoat_<name>`; docs at `hexdocs.pm/managoat_<name>`.

| Package | Latest | What it gives Airlock | What you supply |
|---|---|---|---|
| `managoat_sandbox` | 0.2.1 | The machine layer: create / exec / spawn / attach / suspend / destroy over Sprites, E2B and Daytona, one error taxonomy, a conformance case and a `Fake`. Default-deny egress via `NetworkPolicy`. | Nothing. goatherd already uses it. |
| `managoat_runtimes` | 0.3.0 | Gets claude, codex, gemini or opencode onto a box and up on ACP: pinned adapter versions, file layout, instructions file, skills tree, credential delivery, per-runtime quirks. 0.3.0 adds the optional-callback dispatchers. | Nothing. Pin `~> 0.3`; 0.2.x has no dispatchers. |
| `managoat_acp` | 0.1.2 | The session: `Peer`, `Protocol`, `Blocks`, `Permissions`, `Usage`, `Tracer`. One block format and one permission model across all four runtimes. | Nothing. goatherd already uses it. |
| `managoat_broker` | **0.8.0** | **The reason this product exists.** Rules matching `host[:port][/path]` across six schemes, `unmatched_host_policy: :deny`, expiring sessions, and a terminal per-request telemetry event carrying status, error and duration. | A `Broker.Store` (`Store.Memory` is the reference) and a CA seed. |
| `managoat_runner` | 0.2.1 | The *platform* half of a self-hosted runner: the sandbox adapter, the WebSocket connection process, the host behaviour. **Not the daemon** — that is Go, in Fountain's private CLI, and `FakeDaemon` runs nothing. `NOTES-M0.md` §2. | The `WebSock` transport (Airlock's `Box.Endpoint`), and a `Runner.Host` — which turned out to ship as `Host.Local`, so Airlock configures it rather than writing one. |
| `managoat_substitution` | 0.1.1 | `${VAR}` over nested config, reporting every missing key at once. | Nothing. |
| `managoat_mcp_auth` | 0.1.1 | MCP authorization discovery (RFC 9728 / 8414 / 7591) behind an SSRF guard. | Only once policies can name MCP servers. |
| `managoat_docs` | 0.1.1 | A compile-time embedded manual and its guardrail tests. | Optional, if Airlock grows a `/docs`. |
| `managoat_oauth` | 0.1.1 | Authorization code + PKCE and device grant. | **Not needed.** A single-user app is not an identity provider. |

### Read the library, not Fountain's copy

Much of the design behind `PLAN.md` was derived by reading the **0.1.0** sources
vendored in Fountain's `deps/`. Several libraries have moved well past that —
`managoat_broker` is **seven** minors ahead at **0.8.0**, and `sandbox`,
`runner` and `runtimes` are at 0.2.1. **Verify every API against the version you actually
pin**, and prefer the library's own moduledoc and CHANGELOG to anything
restated here. Those moduledocs are unusually good; they carry the normative
semantics, not just the signatures.

Changes since 0.1.0 that Airlock depends on directly, or that contradict
something written elsewhere in this file:

- **The broker's request event is terminal** (0.3.0). It now carries `status`,
  `error` and a monotonic `duration` alongside `count`, and it fires when the
  request *ends*, not when it starts. Consequence to design around: a
  long-lived request is not recorded until it completes, so an in-flight
  inference call does not appear in the live record until the reply finishes.
  Do not try to fix this with a second event; if start/stop visibility is ever
  needed it is correlated start and stop events, not two meanings on one.
- **`:substitute` rules reach the request target**, not headers alone (0.2.0),
  so a credential a client puts in a URL path is brokerable.
- **Rule matching is by specificity, not declaration order** (0.7.0). The
  *most specific* matched rule sets the header — exact host over wildcard,
  then a pinned port, then the longest literal path prefix — and
  declaration order breaks only what is left. Anywhere below this line
  still says "the first matched rule wins", that line is out of date.
- **`:substitute` placeholders are validated** (0.5.0) and a rule with an
  unusable one is refused: four characters, a letter or digit, a boundary.
  `Injector.valid_placeholder?/1` is public so a host checks where the
  session is built. `Airlock.Policy` checks at parse time.
- **The event's `outcome` is not the record's verdict.** `:passthrough` is
  emitted only when *no rule matched* and the session lets unmatched hosts
  through, so under `unmatched: deny` it is unreachable and a request that
  matched a `:passthrough` rule reports `:injected`. The record derives its
  verdict from the matched rule's scheme instead. `NOTES-M0.md` §4.

## What you actually have to build

Short, because the libraries carry the machine layer and the turn. This is the
whole product.

| Piece | Rough size | Notes |
|---|---|---|
| Policy: parse, store, compile | ~250 lines | YAML in; `Broker.Rule` structs and a `Sandbox.NetworkPolicy` out. goatherd already parses a YAML herd file, so the parsing half has a pattern to follow. |
| Broker wiring and a `Store` | ~200 lines | Start the broker beside the app, mint a session per run, hand the box its proxy address and placeholders. `Store.Memory` is the reference implementation. |
| The record | ~400 lines | A telemetry handler on `[:managoat, :broker, :request]`, storage, and a view with four tabs: Transcript, Egress, Tools, Changes. |
| Provisioning with a policy | ~250 lines | A box up with a runtime on it, plus the network policy and the proxy environment. Airlock writes its own — goatherd's `provision.ex` shares roughly 50 lines and, having no policy step, does not encode the ordering that matters here: packages, skills and npm all run *before* the seal. |
| The thing that drives a turn | ~350 lines | Not goatherd's `driver.ex` — that is deliberately the CLI process, and Airlock has a second consumer and a persisted artefact. |

One deferred extraction: `Fountain.SandboxFiles` (479 lines, Fountain ADR 0039)
is list / read / `git diff` as fixed scripts over `exec`, path-confined and
redacted, and it is provider-neutral already. It is the **Changes** tab. Pull it
out of Fountain into a library when it is needed, not before.

## Shape of the codebase

Settled 2026-09-03. The reasoning for each is in `PLAN.md`'s settled questions.

- **An escript CLI**, like goatherd. Not Phoenix. The record is written out as
  a self-contained HTML file rather than served, because the product claim is
  that you can hand someone the record — and a file is handable in a way a
  localhost route is not. A console can come later; nothing here forecloses it.
- **Not an umbrella.** There is no second deployable and no library being
  extracted here.
- **No database.** Goatherd's finding stands: durability is the sandbox's. The
  record is files on disk.
- **A local box via `managoat_runner`**, which makes the broker trivially
  reachable. Airlock writes the `Runner.Host`. Cloud providers arrive at M3.
- **A box is per-job** and destroyed after, so a run's record describes a box
  nothing else touched.

Because it is an escript, re-read the escript traps below before writing the
entry point: applications are not started, `config/runtime.exs` never runs, and
`function_exported?/3` is not a guard.

## Conventions

- `mix format`, `credo --strict`, `dialyzer`, and compile with
  `--warnings-as-errors`. Wire a `mix precommit` alias that runs the lot, the
  way every managoat library does.
- Tests `async: true` by default. Use the `Fake` adapters the libraries ship
  (`Managoat.Sandbox.Fake`, `Managoat.Runtimes.Testing.FakeRuntime`,
  `Managoat.ACP.Testing.ScriptedAgent`, `Managoat.Runner.FakeDaemon`) rather
  than mocking the libraries.
- Conventional commits, Keep a Changelog, SemVer — the org convention.
- PRs, not direct pushes to `main`.
- Never `Task.async` for fire-and-forget work: it links to the caller and
  nothing awaits it, so a transient failure takes the caller down, and under a
  test sandbox the caller is the test. Use `Task.Supervisor.start_child/2`.

## Traps already paid for

Every one of these was found the expensive way, most of them in Fountain and one
in goatherd. They are not hypothetical.

**Escripts and releases**

- **`function_exported?/3` returns false for a module that is merely not
  loaded**, which in an escript or a release is the normal state of anything
  nobody has called yet. Guarding optional behaviour callbacks with it — the
  obvious idiom — makes every one of them silently no-op. In goatherd this
  dropped the entire inference credential env plus `write_config/2` and
  `prepare_sandbox/3`: provisioning reported every stage green and the agent
  failed minutes later with an authentication error pointing at credentials
  rather than at dispatch. Always
  `Code.ensure_loaded?(mod) and function_exported?(mod, f, a)`. Test it by
  purging the module first, because merely calling the function loads it and
  the test passes either way.

  **For `managoat_runtimes`' own callbacks, do not write the guard at all.**
  0.3.0 shipped `Runtimes.default_env/3`, `write_config/3` and
  `prepare_sandbox/4`, which dispatch and fall back to the documented no-op,
  plus `implements?/3` for `build_command/5`, which has no default. Call
  those. The guard above remains correct for any *other* optional callback
  Airlock dispatches, which is why it stays here.
- An escript does not start applications and never runs `config/runtime.exs`.
  Whatever entry point you write does both jobs explicitly.

**Telemetry**

- **A raising `:telemetry` handler is detached, not retried.** It fails nothing
  and reports nothing; it simply stops running. Airlock's entire record is a
  telemetry handler, so a bug in it looks exactly like an agent that made no
  requests. Guard the handler, test that it survives malformed metadata, and
  assert somewhere that it is still attached.
- Telemetry handlers are global. An `async: true` test that attaches one will
  see events from every other module running concurrently.

**Broker and egress**

- `sudo` strips the proxy environment variables unless sudoers `env_keep` is
  set. An agent that runs anything under `sudo` silently egresses unbrokered,
  or fails.
- Gemini's key is header-only: `x-goog-api-key`, never `?key=` in the query.
- `git` waits for a `407` the proxy has to hold the connection open across;
  broker 0.1.2 fixed this. npm 9 sends no proxy credentials at all.
- `allow_private_upstreams` defaults to `false`. A local test origin needs it
  `true`, and production must never have it on. Note this interacts with the
  local-runner path: a box on your own machine talking to a broker on the same
  machine is exactly the private-upstream case, so think it through rather than
  flipping the flag.
- `Sandbox.NetworkPolicy` with `allow: []` means **deny everything**. At least
  one provider treats an empty rule list as no-enforcement; translating that
  fail-open quirk is the adapter's job and it already does it. Do not
  reimplement it.
- **The runner cannot be sealed at all.** `Runner.Adapter` does not
  advertise `:network_policy` and `apply_network_policy/2` returns
  `{:error, :not_supported}` — "the machine is the user's and so is its
  network". Sprites, E2B and Daytona all support it. This is in direct
  conflict with M0's ordering, which picks the local box *and* makes
  sealing it step 6. `NOTES-M0.md` §1 has the options.
- `Managoat.Sandbox`'s default adapter map holds `sprites`, `e2b` and
  `daytona` only. `:runner` ships in another package, so a host has to
  register it or `build_handle(:runner, _)` raises.

**Sandboxes and runtimes**

- A stream that closes without an exit frame must be surfaced as exit 0, or
  failed commands look successful. Sprites 0.2.2 made a close with no exit
  frame an error.
- The runtime image has no coreutils. A shell builtin is not an executable, so
  `System.cmd` by a bare name can be a no-op that only fails in production
  while every test passes.
- Skills install over npm and GitHub, so it **must** run before the network
  policy locks the box down.
- The agent a runtime provisions for is a **plain map**, not a struct. Your own
  record satisfies it whatever else it carries.

**ACP**

- On reattach, at least one provider replays the last chunk of buffered output
  starting mid-line. `Peer` handles this (`drop_partial_line?`, and the replay
  quiet and max windows) — pass the options, do not hand-roll it.
- opencode never asks for permission. Do not build a permission UI that assumes
  every runtime will use it.
- Gemini reports token usage at `_meta.quota` and never in the protocol's own
  field.
- Claude emits out-of-turn `session_info_update` notifications that look like
  phantom follow-up turns.

## How to work here

- **Read the library moduledocs first.** They state normative semantics and the
  reasoning behind them, and they are more current than this file. Read
  goatherd second, for its two findings and its provisioning module — not as a
  codebase to fork.
- Verify a guard by breaking it. A guard that has stopped guarding looks
  exactly like one that finds nothing.
- When a design question comes up that the libraries answer, follow the
  library. The whole premise of this repo is that the stack already has a
  shape, and the product is what falls out of it.
