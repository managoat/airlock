# M0 notes — what building steps 1–3 found

Written 2026-09-03, against the libraries as actually pinned. `CLAUDE.md`
says to verify every API against the version you pin and to prefer the
library's own moduledoc to anything restated in the brief. Doing that
turned up four things that change the plan, and several smaller ones that
change the code. They are recorded here rather than folded silently into
`PLAN.md`, because two of them are decisions rather than corrections.

**Update, later the same day:** steps 4–9 are now built too, on the
decision recorded in [§7](#7-what-was-decided-and-what-it-changed). Four
more findings came out of that and are in [§8](#8-findings-from-steps-49).

## Contents

1. [Blocking: the local box cannot be sealed](#1-blocking-the-local-box-cannot-be-sealed)
2. [Blocking: there is no runner daemon](#2-blocking-there-is-no-runner-daemon)
3. [The broker is at 0.8.0, not 0.4.0](#3-the-broker-is-at-080-not-040)
4. [The event's `outcome` cannot produce the README's table](#4-the-events-outcome-cannot-produce-the-readmes-table)
5. [Smaller findings](#5-smaller-findings)
6. [Decisions taken](#6-decisions-taken)
7. [What was decided, and what it changed](#7-what-was-decided-and-what-it-changed)
8. [Findings from steps 4–9](#8-findings-from-steps-49)

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

> **Fixed upstream, 2026-09-03.** Filed as managoat_broker#27 and closed in
> **0.11.0**, which adds `scheme` to the request event — the scheme of the
> rule `rule` names. `Airlock.Egress` reads the verdict from it and the
> workaround below is gone: `Airlock.Policy.Compile.rule_schemes/1` and the
> `schemes` field on `Airlock.Broker` are deleted rather than kept beside
> the real answer. The release also documents what `outcome` means in three
> places, which the issue noted would have saved the finding on its own.
> `mix.exs` pins `~> 0.11.0`; 0.10 and earlier cannot say.
>
> The rest of this section is what was found and why, kept because the
> reasoning is what a reader of the record still needs.


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

The event carried the rule's **name** but not its **scheme**. Airlock
compiles its own rules, so it could put the two back together from the
name — but a consumer whose rules come from a tenant's binding or a
catalog default could not, and neither could anything reading the events
out of band. Names are not unique either. That is what made it worth
filing rather than working around, and `scheme` is what shipped.

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


---

## 7. What was decided, and what it changed

Settled 2026-09-03, after §1's options were put side by side:

**The box is Sprites, reached over a tunnel** — option (c), pulling M3's
reachability forward. The reasoning that decided it: the local runner was
chosen in `PLAN.md` because it was the *cheapest* path to a reachable
broker, and both blockers say it is not cheap. It needs a daemon that is
not public, and it can never be sealed. Sprites needs a tunnel and nothing
else, and goatherd has already proved the provisioning path.

So M0's ordering inverts. The local box is no longer the M0–M2 box; it is
a path Airlock still supports (`--provider runner`) and cannot seal, and
`Airlock.Run` refuses to run on it unless told `--unsealed` in as many
words.

`Airlock.Test.FakeBox` gets option (b) as well, for free: the fake
advertises `:network_policy`, so the seal is genuinely applied in
`Airlock.RunTest` and read back off the box while the turn is running.
That is the test `PLAN.md` asked for.

**Both library findings were filed:** managoat_broker#27 (the event cannot
distinguish a matched `:passthrough` rule from an attached credential) and
managoat_runner#4 (should the daemon protocol ever carry a seal).

## 8. Findings from steps 4–9

### `SPRITES_TOKEN` in the environment did nothing

The escript trap, in its purest form. Every `managoat_sandbox` adapter
reads its own application environment — `Managoat.Sandbox.Config.get(Sprites,
:token)` — which in a mix project `config/runtime.exs` fills in. **An
escript never runs it.** So `SPRITES_TOKEN=… airlock run` died inside the
library with

    ** (RuntimeError) SPRITES_TOKEN is not set — cannot talk to sprites.dev

while the variable was plainly set in the shell that ran it. `Airlock.Boot`
now lifts the provider credentials into the libraries' config itself, and
`Airlock.Run` preflights them so a missing one is an error naming the
variable rather than a raise several frames down.

### The peer's default permission policy is `auto_allow`

`Managoat.ACP.Permissions.verdict_for/2` falls back to `auto_allow` when a
policy names nothing, and `Managoat.ACP.Peer` starts with
`permission_policy: %{}`. A peer started the obvious way therefore
**approves every tool call itself**, and the `{:permission_ask, …}` report
never reaches its owner.

That is a fair default for an interactive product with a human in the loop.
It is the wrong one for M0, which runs one prompt unattended on a box
holding a live proxy address. `Airlock.Run` names `%{"default" => "ask"}`
explicitly and denies what arrives, because there is nobody to ask.

Worth knowing rather than filing: the library is not wrong, but "start a
peer and you have an auto-approving agent" is a sharp edge for a host that
does not read `Permissions` first.

### `Managoat.Sandbox.Fake` raises on any argv but its own

The Fake's commands speak `out:` / `err:` / `exit:` / `stay` / `drop`, and
anything else is a `FunctionClauseError` out of `Fake.script/1` — not a
nonzero exit, a raise. Its moduledoc lists "drive a provisioning path
without a network" as one of its three jobs, and no real provisioning path
survives it: every step is `bash -lc <script>`, starting with
`Managoat.Runtimes.ACP.install/3`'s npm install.

`test/support/fake_box.ex` wraps it so `exec/4` is total. Worth filing;
not yet filed.

### The block key is `:body`, not `:text`

`Managoat.ACP.Blocks` emits `%{kind: :text, body: "…"}`. Reading `:text`
gets `nil` on every block and concatenates to `""` — an agent that said
nothing, which is exactly what a broken transcript should not look like.
Caught by a test that asserted on content rather than on shape.

### `Managoat.Runner.Names` decides no placement, so Airlock does

A runner sandbox name carries the runner id (`runner-<32 hex>-<8 hex>`),
because a name is the only thing `Managoat.Sandbox` hands an adapter.
`Names`' moduledoc says which runner a *new* sandbox lands on "is the
host's placement policy and is not here" — correct, and it means a host
that mints an ordinary name gets `{:invalid, {:not_a_runner_sandbox_name,
…}}` at create. `Airlock.Box.name_for/2` mints per provider.

### The token rides in the clear over a tunnel

Not a library finding — an architecture one, and the reason
`Airlock.Broker.Reachability` exists. `Managoat.Broker`'s listener is
plaintext by construction (`port` is documented as "the plaintext listener
port"; there is no TLS option). Over a tunnel to a cloud sandbox, every
request carries `Proxy-Authorization: Basic base64(token:label)` over the
public internet, and that token is the authority to use every credential
the policy names.

Bodies are safe — they are TLS inside the `CONNECT` tunnel — but the token
and the host list are not. Mitigated by `expires_in` and a per-run token;
fixed only by a tailnet or a TLS listener. `airlock run` prints the warning
rather than swallowing it.

Also worth recording: **`cloudflared` quick tunnels do not work at all**.
They are HTTP reverse proxies and will not forward `CONNECT`. A raw TCP
tunnel (`ngrok tcp`) does.

### The tunnel is the blocker, not the code

`sprite login` on 2026-09-03 gave Airlock a real Sprites account, and
`Airlock.Credentials` now finds both credentials a run needs without
anything being exported — the Sprites token from `~/.sprites/sprites.json`
plus the login keychain, and a `CLAUDE_CODE_OAUTH_TOKEN` from Claude Code's
own keychain item. goatherd's `keychain.ex` transferred as `CLAUDE.md` said
it would, `go-keyring-base64:` marker and all; the token on this machine is
stored wrapped, so the unwrap is load-bearing rather than defensive.

What is missing is a way for a Sprites sandbox to reach a broker on this
laptop. Four were tried:

| | |
|---|---|
| `ngrok tcp` | account suspended for a failed payment |
| `tailscale funnel --tcp` | raw TCP forwarder, exactly right — **not on the Starter plan** |
| `cloudflared` | quick tunnels are HTTP reverse proxies and will not forward `CONNECT`; a named tunnel needs an authenticated origin cert, and its TCP mode needs `cloudflared access` on the *client*, which is the sandbox |
| `ssh -R` to serveo.net | remote port forwarding refused |

Tailscale itself is installed and the tailnet is up, which points at the
architecturally right answer and its wrinkle: put the **sandbox** on the
tailnet, so the hop is encrypted between peers and nothing is public. The
wrinkle is that a mesh VPN needs its own egress — `controlplane.tailscale.com`
and the DERP relays — so the seal can no longer be "the broker and nothing
else". It becomes "the broker and the VPN's control plane", which is a
wider allow list than `Airlock.Policy.Compile` argues for and needs that
argument re-made rather than quietly widened.

### Still not verified

No agent has run. There are no Sprites credentials on this machine — no
`SPRITES_TOKEN`, no `~/.sprites/sprites.json`, no `sprites` CLI — so
everything above is tested against `Managoat.Sandbox.Fake`,
`Managoat.ACP.Testing.ScriptedAgent` and a real broker with a real origin.
What that leaves unproven is the one thing M0 exists to answer: whether a
real agent does real work with credentials it never holds.

To find out:

    export SPRITES_TOKEN=...            # or ANTHROPIC_API_KEY for the policy
    ngrok tcp <the broker port>
    airlock run policy.yaml "..." --broker-host 4.tcp.ngrok.io:19482
