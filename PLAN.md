# Airlock — build plan

Read `CLAUDE.md` first; it is the brief and the boundary. This file is the
order of work and the acceptance criteria.

M0 is **done** as of 2026-09-03 — run for real, against Sprites, with the
record to show for it. Everything below it is not built. Each milestone lists what "done" means concretely, because
"M1 is finished" is otherwise a matter of opinion. `NOTES-M0.md` records
what building those three steps found, including two blockers further down
M0 and several corrections to this file.

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

1. Brings up a `Runner.Host` so `managoat_runner` can present a local box.
   Genuinely first — everything below needs a box, and `Host.Local` over a
   plain `Registry` is a guess the brief makes, not a measurement.
2. Reads a policy file and credentials from the environment.
3. Starts the broker with a `Store.Memory` holding one session compiled from the
   policy's `credentials`, with `unmatched_host_policy: :deny`.
4. Provisions a box — **still unsealed**. Packages, skills and npm all reach
   the network here, so no `NetworkPolicy` yet.
5. Brings up one runtime on it, with the inference credential delivered as a
   `:substitute` placeholder rather than the real value, and the proxy
   environment pointing at the broker. Dispatch the runtime's optional
   callbacks through `Runtimes.default_env/3` and friends; never write the
   `function_exported?/3` guard.
6. **Seals the box**: `apply_network_policy/2` from the policy's `allow` list.
   This is the last thing before the agent runs, and it is the step with no
   prior art — goatherd never sealed a box — so it is the part worth a test.
7. Runs one prompt to completion over `Managoat.ACP.Peer`.
8. Prints the transcript, and the egress log from a telemetry handler on
   `[:managoat, :broker, :request]`.
9. Destroys the box.

Note that steps 3 and 6 interact: the box reaches its allowed hosts *through*
the broker, so whatever the seal permits has to include the broker's own
address. Work out what `allow` compiles to on both layers before writing
either — it is the first place the two-layer design gets tested for real.

The box is **local**, via `managoat_runner`, so reachability is not a variable
while the credential path is being proven. Mind that this is exactly the
`allow_private_upstreams` case; think it through rather than flipping the flag.

**Done when:** the agent completes a task that requires network access; the box
never held a real credential; and the egress log shows at least one `injected`
row, one `passthrough` row and one `denied` row, each naming the rule that
decided it.

> **Done, 2026-09-03.** A real Claude agent ran on a sealed Sprites box
> holding `PLACEHOLDER-AIRLOCK-ANTHROPIC`, fetched a host the policy
> allowed, was refused one it did not, and the box was destroyed. The
> record carried all three verdicts, each naming its rule. `NOTES-M0.md` §9
> has it.
>
> **Two things in this ordering were wrong, and are corrected there:**
>
> - **step 1's box cannot be sealed.** `Runner.Adapter.apply_network_policy/2`
>   refuses outright, and there is no public runner daemon. The box is
>   Sprites over a tunnel, which pulls M3's reachability forward;
> - **there is a step between 4 and 5**: the box has to trust the broker's
>   root, or it cannot complete a TLS handshake through it with anything.
>
> Also worth carrying forward: `passthrough` in the sentence above is not
> the event's `outcome` (§4), and provisioning deliberately does not go
> through the broker (§9), so what it fetched is not in the record.

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

The view is an exported HTML file, not a server — settled question 3. So
"export a run as a single file someone else can read" is not a separate bullet
from the four tabs above; it is the same artefact. Build the tabs into the
export rather than building a view and an exporter.

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
    username: x-access-token   # required; :basic is a pair, NOTES-M0.md §5
    from: env:GITHUB_TOKEN

unmatched: deny
expires_in: "4h"
```

Three notes before implementing it:

- `allow` and `credentials` are different layers. `allow` is the sandbox's own
  default-deny egress policy; `credentials` is what the proxy does with a request
  that got out. A host in `credentials` must also be in `allow`.
- Several rules may match one request. ~~The first matched rule that sets a
  header wins~~ — **out of date as of broker 0.7.0.** The *most specific*
  matched rule sets the header: exact host over wildcard, then a pinned
  port, then the longest literal path prefix, and declaration order breaks
  only what is left. Every matched `:substitute` rule still applies, in
  declaration order. Preserve that ordering when compiling — it is the
  library's contract, not an accident. `NOTES-M0.md` §3.
- **One host may need more than one credential.** `api.anthropic.com` can carry
  both a subscription token and an API key, because an org can refuse the OAuth
  token mid-conversation and `Claude.fall_back_to_api_key/2` swaps to the key
  on a box that is already running. So `credentials` is a list keyed by nothing
  — do not collapse it to a map on `host`, and mint the broker session with
  every placeholder a run might need rather than only the one provisioning
  chose. See settled question 2.

---

## Settled questions

All four were open; all four are settled as of 2026-09-03. Each records what
would reopen it, because a decision without a revisit condition is just a
habit.

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

   M0 pins `{:managoat_runtimes, "~> 0.3"}`. Anything resolving to 0.2.x gets
   a library without the dispatchers.
2. ~~**Claude subscription auth versus an API key.**~~ **Settled 2026-09-03:
   support both.** Cheaper than it looks, because the library already does it:
   `Claude.default_env/2` prefers `CLAUDE_CODE_OAUTH_TOKEN` when present and
   falls back to `ANTHROPIC_API_KEY`, deliberately never exporting both,
   because mixing them picks the wrong one depending on CLI version. Both are
   bearer-shaped on the wire, so both broker identically through a
   `:substitute` rule — the containment claim does not weaken.

   Two consequences to design around rather than discover:

   - `Claude.fall_back_to_api_key/2` exists because an org can refuse an OAuth
     token **mid-conversation**, after provisioning has already chosen. For
     Airlock that means a policy may need to carry *two* credentials for
     `api.anthropic.com`, and the broker session must hold both placeholders
     from the start — a session minted with only the OAuth rule cannot serve
     the fallback. Design the schema for it even if M0 only exercises one.
   - The terms-of-service question the original entry raised is about **a box
     someone else operates**. Through M2 the box is the user's own machine, so
     it does not bite. Do the read before M3, not before M0.

3. ~~**Server, CLI, or both.**~~ **Settled 2026-09-03: an escript CLI, and the
   record is an exported HTML file.** The plan's own line — the record is a
   page, not necessarily a server — decides it. The product claim is that you
   can hand someone the record, and a file is handable in a way a localhost
   route is not. goatherd proves the escript shape works on this substrate.

   **Revisit when** something needs the record to be *live* rather than final —
   watching a long run, or the M4 notification when a session blocks on a
   permission request. That is a real trigger, not a maybe; it just is not yet.

4. ~~**Whether a box is per-job or per-project.**~~ **Settled 2026-09-03:
   per-job, destroyed after the run.** It is the containment story, and it is
   what makes the record honest: a run's diff is relative to a known starting
   state rather than to whatever the last run left behind. The cost is full
   provisioning per run, which `CLAUDE.md` says explicitly does not matter —
   Airlock is optimised to be safe to leave, not to start fast.

   **Revisit when** M3's policy templates want a warm box for a repeat job, at
   which point the honest answer is a `lifetime:` key in the policy rather than
   a silent change of default.
