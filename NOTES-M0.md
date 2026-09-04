# M0 notes — what building steps 1–3 found

Written 2026-09-03, against the libraries as actually pinned. `CLAUDE.md`
says to verify every API against the version you pin and to prefer the
library's own moduledoc to anything restated in the brief. Doing that
turned up four things that change the plan, and several smaller ones that
change the code. They are recorded here rather than folded silently into
`PLAN.md`, because two of them are decisions rather than corrections.

## Contents

1. [Blocking: the local box cannot be sealed](#1-blocking-the-local-box-cannot-be-sealed)
2. [Blocking: there is no runner daemon](#2-blocking-there-is-no-runner-daemon)
3. [The broker is at 0.8.0, not 0.4.0](#3-the-broker-is-at-080-not-040)
4. [The event's `outcome` cannot produce the README's table](#4-the-events-outcome-cannot-produce-the-readmes-table)
5. [Smaller findings](#5-smaller-findings)
6. [Decisions taken](#6-decisions-taken)

---

## 1. Blocking: the local box cannot be sealed

`Managoat.Runner.Adapter`, 0.2.1, moduledoc:

> `:network_policy` is **not** [advertised] — the machine is the user's and
> so is its network; `apply_network_policy/2` refuses rather than
> pretending.

```elixir
def apply_network_policy(%Handle{}, %NetworkPolicy{}), do: {:error, :not_supported}
```

Sprites, E2B and Daytona all advertise `:network_policy`. The runner is the
only adapter that does not. It goes deeper than the Elixir adapter: the Go
daemon's `Backend` interface (`cli/internal/runner/backend.go`) has no
network-policy method at all, so the wire protocol has no such request to
carry.

**Why this reorders M0.** `PLAN.md` picks the local box *because* the
broker has to be reachable from it, and then makes sealing the box step 6 —
"the last thing before the agent runs, and it is the step with no prior art
— so it is the part worth a test". The box chosen for reachability is the
one box that cannot be sealed. Steps 1 and 6 are in direct conflict, and
nothing in the brief flags it because the brief was written from the 0.1.0
sources.

Pinned by a test: `test/airlock/box/endpoint_test.exs`, "it refuses to be
sealed, which is M0 step 6".

**What it costs.** Less than it sounds, and only because of the decision in
[§6](#the-two-layer-answer-allow-compiles-onto-the-broker). Airlock's
network policy is `allow: [broker_host]` — one destination — and its job is
to force every request through the chokepoint that logs it. On a local box
that guarantee is unenforced: nothing stops a process on your own machine
opening a socket to anywhere. The **credential** containment still holds
completely (the box never holds a real key, the proxy attaches it), and so
does the record *for anything that uses the proxy*. What is lost is the
guarantee that there is nothing else.

**The options, in the order I would take them:**

| | |
|---|---|
| **a. Say so, and seal at M3** | Keep the local box for M0–M2 as the credential path, and be explicit that it is unsealed. The seal arrives with the cloud providers, which all support it. Cheapest, and honest — but the seal, which `PLAN.md` calls the part worth a test, then goes untested until M3. |
| **b. Seal against `Managoat.Sandbox.Fake`** | `Fake` advertises `:network_policy`. Add step 6 as a test against it now, so the compile-and-apply step is written and exercised, and the first real seal at M3 is a change of adapter rather than new code. Costs about an afternoon. **This is what I would do**, alongside (a). |
| **c. Pull M3 forward** | Go straight to Sprites and solve reachability with a tunnel. Gets a genuinely sealed box, and buys the deployment story `PLAN.md` deliberately deferred. Largest change to the plan. |
| **d. Seal locally by other means** | pf/nftables rules around the daemon's processes. Not `managoat_sandbox`'s abstraction, per-platform, and it is the kind of thing the boundary section of `CLAUDE.md` exists to refuse. |

Not a decision I should take alone; (a) + (b) is the recommendation.

## 2. Blocking: there is no runner daemon

`managoat_runner` ships the platform half only. The daemon that would
actually run commands on your machine is not in any of the nine libraries
and is not on hex:

- `Managoat.Runner.FakeDaemon` is an in-BEAM stand-in. Its sandboxes are
  maps of files and its commands are scripted (`out:`, `err:`, `exit:`,
  `stay`, `drop`) — the same vocabulary as `Managoat.Sandbox.Fake`. It runs
  nothing. Its own moduledoc: "the Go daemon must agree with it";
- the Go daemon is `fountain runner`, in Fountain's private CLI:
  `cli/internal/runner`, about 4,300 lines across a WebSocket connection, a
  process backend and a Firecracker backend.

So "a local box via `managoat_runner`" needs either a dependency on
Fountain's CLI or a daemon Airlock writes. Neither is in `PLAN.md`'s
estimate, and the second is a much bigger job than the five rows in
`CLAUDE.md`'s "what you actually have to build" table.

**What is built and verified anyway.** The half that *is* Airlock's:

- `managoat_runner` depends on `websock` (the behaviour) only, and says the
  adapter mounting a handler on a Plug connection "belongs to the host
  application". `Airlock.Box.Endpoint` is that — Bandit, one authenticated
  route, `WebSockAdapter.upgrade/4`;
- `Airlock.Test.DaemonClient` speaks the daemon's side of the protocol over
  a real socket, so the upgrade, the token check, the registration and one
  `Managoat.Sandbox.get/1` round trip are verified end to end rather than
  against the library's in-BEAM stand-in.

What is not verified is a box: nothing creates a directory or runs a
command.

**Also here:** `Managoat.Sandbox`'s default adapter map is `sprites`, `e2b`
and `daytona`. `:runner` is not in it — it ships in a different package, so
no default could have included it — and `Sandbox.build_handle(:runner, _)`
raises "unknown sandbox provider" until a host registers it.
`Airlock.Box.Host.configure/0` does.

## 3. The broker is at 0.8.0, not 0.4.0

`CLAUDE.md` records `managoat_broker` at 0.4.0 and says it is "three minors
ahead" of the 0.1.0 sources the design was read from. It is at **0.8.0**;
0.5.0 through 0.8.0 were all released 2026-09-03. Every other library
matches what the brief says.

Four releases matter to code already written:

- **0.7.0 changed rule matching from declaration order to specificity.**
  `CLAUDE.md` and `PLAN.md` both still state the old contract — "the first
  matched rule that sets a header wins ... Preserve that ordering when
  compiling — it is the library's contract, not an accident." It is no
  longer the contract. The most *specific* matched rule sets the header:
  exact host over wildcard, then a pinned port, then the longest literal
  path prefix, and declaration order breaks only what is left. The release
  notes are worth reading: under the old rule a defaults-then-overrides
  list silently used the default, the request *succeeded*, and the event
  named the rule that had won — so the audit log looked fine too.
- **0.5.0 validates `:substitute` placeholders** and refuses a rule with an
  unusable one (four characters, a letter or digit, a boundary).
  `Injector.valid_placeholder?/1` is public so a host can check where the
  session is built; `Airlock.Policy` calls it at parse time, so a bad
  placeholder fails in the file rather than on every request it matches.
- **0.6.2** turned a matched rule with no usable credential from a
  `FunctionClauseError` into a `502` with `error: :credential_missing`.
  Worth knowing because that is the shape of an unprovisioned credential,
  and it is a row in the record rather than a crash.
- **0.8.0** added `request_read_timeout`, five minutes by default, on
  reading one request. Not the response — a `git clone` or an SSE stream is
  deliberately outside it.

`mix.exs` pins `~> 0.8.0`.

## 4. The event's `outcome` cannot produce the README's table

The sharpest of the small findings, because it reads as though it works.

`[:managoat, :broker, :request]` carries `outcome`, documented as
`:injected`, `:passthrough` or `:denied`. In `Managoat.Broker.Proxy`:

```elixir
{:ok, nil}   -> {:passthrough, nil}
{:ok, rule}  -> {:injected, rule}
{:error, _}  -> {:denied, nil}
```

and in `Injector.inject/5` the `nil` arises only when **no rule matched at
all** and `unmatched_host_policy` is `:passthrough`.

So: **`outcome: :passthrough` is unreachable under `unmatched: deny`.** A
request that matched a `:passthrough` rule and had nothing whatsoever
attached to it is reported as `:injected`, because a rule matched.

Taken at face value, `README.md`'s table is wrong — its
`registry.npmjs.org … passthrough` row would read `injected`, and so would
every other allowed host. The question the record exists to answer, *which
requests actually carried one of my credentials*, would have no answer in
it.

The event carries the rule's **name** but not its **scheme**, and Airlock
compiled the rules, so it is the one place the two can be put back
together. `Airlock.Policy.Compile.rule_schemes/1` supplies name → scheme
and `Airlock.Egress` derives the verdict from it. That is what produces the
table in [§6](#it-works). Nothing about it is a workaround the library
needs to fix — the library's `outcome` answers "did a rule apply", which is
a different and also reasonable question.

## 5. Smaller findings

- **`YamlElixir.read_from_string/1` hangs on an unclosed flow sequence.**
  `"allow: [a.com\ncredentials:"` spins inside yamerl indefinitely, using a
  core, rather than returning an error. Unbounded, a typo in a policy file
  hangs `airlock` with no output and nothing to read.
  `Airlock.Policy.read_yaml/1` bounds the parse at five seconds. Pinned by
  a test.
- **A runner id has to be canonicalised before it registers.** The adapter
  is handed nothing but a sandbox name, parses the runner id back out of it
  with `Managoat.Runner.Names.parse/1`, and looks *that* up. `parse/1`
  returns the lowercase dashed UUID. A daemon dialling in with an undashed
  or uppercase id registers under a key nothing looks up, and every call
  comes back `{:unavailable, :runner_offline}` — transient in the taxonomy,
  so a caller retries a runner that is connected and will never answer.
  `Airlock.Box.Endpoint` canonicalises.
- **`:basic` needs a username the policy schema did not have.**
  `Managoat.Broker.Rule`'s `:basic` credential is a `{username, password}`
  pair; a policy names one environment variable. Both orders are real —
  GitHub takes `x-access-token:<token>` *and* `<token>:x-oauth-basic` — so
  guessing would produce a `401` the author has to work backwards from.
  `username:` is required, which means **the example policy in `PLAN.md`
  and `README.md` is not valid as written**; `priv/policies/example.yaml`
  has the corrected form.
- **The `:custom` scheme is not built.** It needs a credential that is a
  map of keys rather than one value. Refused by name, per `CLAUDE.md`'s
  rule about unbuilt behaviour.

## 6. Decisions taken

### The two-layer answer: `allow` compiles onto the broker

`PLAN.md`: "Work out what `allow` compiles to on both layers before writing
either — it is the first place the two-layer design gets tested for real."

    NetworkPolicy{allow: [broker_host]}          # the box: one way out
    [credential rules] ++ [passthrough rules]    # the proxy: which hosts, with what

The box's egress policy names **the broker and nothing else**. Each `allow`
entry becomes a `:passthrough` rule at the proxy, with
`unmatched_host_policy: :deny` refusing everything else.

The obvious alternative is `allow ++ [broker]` on the box — belt and
braces. It is weaker. A box that may reach `github.com` directly can reach
it *without* the proxy, and `CLAUDE.md` already records two things that do
exactly that: `sudo` stripping the proxy environment, and npm 9 sending no
proxy credentials. Under `allow ++ [broker]` such a request egresses to an
allowed host unbrokered and therefore **unrecorded** — the record shows
nothing and nothing failed. Under `allow: [broker]` it fails to reach
anything, which is loud.

A passthrough rule is emitted for *every* allowed host, including hosts
that also have a credential rule, because a credential rule may be narrower
than the host (`github.com/managoat/*`) and `allow: [github.com]` said the
host is reachable. It is safe because 0.7.0 pins that `:passthrough` never
displaces a rule that injects.

### `allow_private_upstreams` stays `false`

`CLAUDE.md` flags the local box as "exactly the private-upstream case" and
says to think it through rather than flip the flag. Thinking it through:
the flag governs which **upstreams the proxy may dial**, and the
box-to-proxy connection is not an upstream — the box is a client of the
listener. The origins the broker then dials are public. So the flag is not
implicated by a local box at all and stays `false`. It is `true` in
`broker_test.exs` only, where the origin genuinely is on loopback, which is
what the option is documented for.

### `Host.Local` is not rewritten

`CLAUDE.md`: "`Host.Local` over a plain `Registry` is the guess; it is M0's
first task and the guess is unverified." Measured: the library **ships**
`Managoat.Runner.Host.Local`, it is exactly that, its own tests run against
it and its moduledoc says a consumer without a cluster uses it as-is. So
the guess was right and there is nothing to write. Airlock supplies the
supervision and the two application-environment keys instead.

### It works

`airlock broker` against a real policy, with `curl` standing in for a box:

```
VERDICT      METHOD  HOST                  PATH                  RULE                STATUS TIME
passthrough  GET     example.com           /                     allow:example.com   200    8.9ms
injected     GET     httpbin.org           /bearer               demo-api            200    444.3ms
denied       GET     pastebin.com          /raw/x9f2             —                   403    0.0ms
denied       GET     169.254.169.254       /latest/meta-data/    —                   403    0.0ms
```

The origin at `httpbin.org/bearer` answered
`{"authenticated": true, "token": "super-secret-demo-token"}` — the client
sent no credential, and the last two rows are the ones the README is about.

That is M0's "done when" for the egress log, minus the agent: steps 4
through 9 are not built, and step 6 cannot be on this box.
