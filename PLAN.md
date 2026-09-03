# Airlock — build plan

Read `CLAUDE.md` first; it is the brief and the boundary. This file is the
order of work and the acceptance criteria.

Nothing below is built. Each milestone lists what "done" means concretely,
because "M1 is finished" is otherwise a matter of opinion.

Two things set this ordering, and both come from `CLAUDE.md`:

- **The broker must be reachable from the box.** A cloud sandbox cannot dial a
  proxy on your laptop, so the cheapest working Airlock puts the box on your own
  machine via `managoat_runner` and the broker beside it. The cloud path is the
  one that needs a deployment story.
- **Durability is the sandbox's.** A detachable ACP session plus a pointer is
  enough; there is no session database to build.

---

## M0 — one agent, contained

**The question this answers:** does an agent do real work with credentials it
never holds, and does the egress log come out legible?

A throwaway is fine. `mix new`, the hex packages, no console, no database. A
script that:

1. Reads a policy file and credentials from the environment.
2. Provisions a box with `NetworkPolicy` set from the policy's `allow` list.
3. Starts the broker with a `Store.Memory` holding one session compiled from the
   policy's `credentials`, with `unmatched_host_policy: :deny`.
4. Brings up one runtime on the box, with the inference key delivered as a
   `:substitute` placeholder rather than the real value.
5. Runs one prompt to completion over `Managoat.ACP.Peer`.
6. Prints the transcript, and the egress log from a telemetry handler on
   `[:managoat, :broker, :request]`.

Do it against a **local box** first — `managoat_runner`, or any sandbox on the
same machine as the broker — so reachability is not a variable while the
credential path is being proven. Mind that this is exactly the
`allow_private_upstreams` case; think it through rather than flipping the flag.

**Done when:** the agent completes a task that requires network access; the box
never held a real credential; and the egress log shows at least one `injected`
row, one `passthrough` row and one `denied` row, each naming the rule that
decided it.

**Deliberately not measuring cold start.** It stopped being the risk when the
product stopped being about burst parallelism.

---

## M1 — the policy is a real object

- The policy file format below: parsed, validated, compiled to `Broker.Rule`
  structs and a `Sandbox.NetworkPolicy`.
- Validation that catches the mistakes that would otherwise be silent: a host in
  `credentials` that is not in `allow` can never match, and should be an error
  rather than a dead rule.
- A `Broker.Store` that outlives one process, so a run's proxy session survives
  the thing that started it.
- Reattach: `Sandbox.attach/3` replays from byte zero, so de-duplicate by
  counting bytes already persisted per stream. Pass `Peer`'s replay options
  rather than hand-rolling the mid-line handling.

**Done when:** the same policy file, checked into a repository, produces the
same containment on two different machines, and a run survives the client going
away and coming back.

---

## M2 — the record

What turns a utility into a product.

- Storage for a run: transcript, egress rows, spans, usage.
- A view with four tabs:
  - **Transcript** — `Managoat.ACP.Blocks`, never a runtime dialect.
  - **Egress** — every request: method, host, path, verdict, rule, status,
    latency, error.
  - **Tools** — spans from `Managoat.ACP.Tracer`, plus normalised token usage
    from `Managoat.ACP.Usage`.
  - **Changes** — the diff. This is where `Fountain.SandboxFiles` gets extracted
    into a library; not before.
- Export a run as a single file someone else can read.

Whether the view is Phoenix from the start or an exported HTML file first is
deliberately open. The record is a page, not necessarily a server.

**Done when:** an agent given a scoped API key tries to reach a host the policy
does not name, and the run record shows the denial, the rule and the moment it
happened, without you having gone looking for it.

---

## M3 — the cloud path

Everything above works with the box and the broker on one machine. This is the
milestone that earns the deployment.

- A reachable broker address, and the box configured to use it.
- Sprites, E2B and Daytona as box providers alongside the local runner.
- Policy templates for the obvious cases: a read-only box, a box that may reach
  one vendor API, a box that may push to one repository.

**Done when:** the same policy and the same record work with the box on someone
else's hardware.

---

## M4 — living with it

- A cost meter: sandbox seconds plus tokens from `Usage`.
- Notifications when a session is blocked on a permission request.
- Optional: **bakeoff mode** — one prompt, several runtimes, records compared
  side by side. Nearly free once M1 and M2 exist, and the best demo of four
  runtimes behind one protocol that anyone will build.

---

## The policy file

The shape to aim for. It maps one-to-one onto `Managoat.Broker.Rule` and
`Managoat.Sandbox.NetworkPolicy`, which is the tell that this is the product the
stack was already shaped for.

```yaml
# the complete list of hosts this job may reach; everything else is denied
allow:
  - github.com
  - registry.npmjs.org
  - api.stripe.com

credentials:
  # the box never sees these values
  - host: api.stripe.com
    scheme: bearer
    from: env:STRIPE_RESTRICTED_KEY

  - host: api.anthropic.com
    scheme: substitute          # the agent sends the key itself
    placeholder: "PLACEHOLDER-ANTHROPIC"
    from: env:ANTHROPIC_API_KEY

  - host: "github.com/managoat/*"
    scheme: basic
    from: env:GITHUB_TOKEN

unmatched: deny
expires_in: "4h"
```

Two notes before implementing it:

- `allow` and `credentials` are different layers. `allow` is the sandbox's own
  default-deny egress policy; `credentials` is what the proxy does with a request
  that got out. A host in `credentials` must also be in `allow`.
- Several rules may match one request. The first matched rule that sets a header
  wins, and every matched `:substitute` rule applies. Preserve that ordering when
  compiling — it is the library's contract, not an accident.

---

## Open questions

1. ~~**Is provisioning the tenth library?**~~ **Settled 2026-09-03: no.** M0
   writes its own provisioning. The two-consumers signal misfires because the
   two consumers are not consumers of the same thing — roughly 50 of
   `provision.ex`'s 227 lines transfer. Its `packages` / `clone` / `setup`
   steps read herd-file fields the policy schema does not have; its
   `sprite_env/4` lifts real secrets from the local shell *into* the box,
   which is the exact inversion of what Airlock does. Decisively: goatherd
   never calls `Sandbox.apply_network_policy/2` and never installs skills, so
   the ordering its moduledoc calls the hard-won part is a strict subset of
   Airlock's, missing the terminal seal and the
   skills-before-lockdown constraint that `Runtimes.Skills` documents.
   Extracting now would freeze a sequence before the only product with a
   policy has ever run one. There is also no proxy or CA handling anywhere in
   the nine libraries, so the piece Airlock adds has no second consumer at all.

   **Revisit when** a third consumer needs the *sealed* ordering — provision,
   then apply a network policy — not merely "a box with a runtime on it". At
   that point the thing to extract is the seal, and Airlock will have run it
   in anger.

   **The extraction that was real, and it was not a tenth library — now
   shipped.** `Managoat.Runtimes` declared four optional callbacks and no safe
   way to call them, so every host had to rediscover the `function_exported?`
   trap on the library's own callbacks. Filed as managoat/managoat_runtimes#7
   and released in **0.3.0**: `default_env/3`, `write_config/3` and
   `prepare_sandbox/4` dispatch and fall back to the documented no-op, and
   `implements?/3` answers the same question for `build_command/5`, which has
   no default to fall back to. All four call `Code.ensure_loaded?/1` first.

   **So Airlock never writes the guard for these callbacks — it calls the
   dispatchers.** The trap still applies to any *other* optional-callback
   dispatch Airlock writes; see `CLAUDE.md`.

   One catch for M0's `mix.exs`: **0.3.0 is on `main` but not published to
   hex** — hex's latest stable is still 0.2.1. Until it is published, reaching
   the dispatchers means a git dependency. Not blocking, because no code
   exists yet, but decide it deliberately rather than pinning `~> 0.2` and
   quietly getting a library without them.
2. **Claude subscription auth versus an API key**, on a box someone else
   operates. The API key path is unambiguous and is what `managoat_runtimes`
   already does. Subscription auth is what most people are actually on, and it
   needs a terms-of-service read before it goes near a design.
3. **Server, CLI, or both.** M0 needs neither. M2's record wants a page. Decide
   when the record forces it, not before.
4. **Whether a box is per-job or per-project.** M0 and M1 do not need the
   answer; M3's policy templates might.
