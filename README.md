# Airlock

Run a coding agent on a machine you chose, with credentials that machine never
holds, and get a record of everything it did.

> **Status: M0 done.** A real Claude agent has run on a sealed cloud box
> holding a placeholder where the API token should be, fetched a host the
> policy allowed, been refused one it did not, and the box was destroyed
> after. The table below is from that run, not a mock-up.
>
> **Not built:** the record's Tools and Changes tabs (M2, in progress),
> sessions do not survive the client going away (M1), and Sprites is the
> only cloud provider wired up (M3).
>
> The brief is [CLAUDE.md](CLAUDE.md), the plan is [PLAN.md](PLAN.md), and
> [NOTES-M0.md](NOTES-M0.md) records what building it found.

## The idea

You write a policy: the complete list of hosts a job may reach, and which
credential goes to which host.

```yaml
allow:
  - github.com
  - registry.npmjs.org
  - api.stripe.com

credentials:
  - host: api.stripe.com
    scheme: bearer
    from: env:STRIPE_RESTRICTED_KEY

  - host: api.anthropic.com
    scheme: substitute          # the agent sends the key itself
    placeholder: "PLACEHOLDER-ANTHROPIC"
    from: env:ANTHROPIC_API_KEY

unmatched: deny
```

Airlock provisions a box, brings up a coding agent on it, and lets the agent
work. The agent sees placeholders where your keys should be. The real
credentials are attached at a proxy that is the box's only way out, so a
placeholder lifted off the disk is worth nothing anywhere else.

Then you get the record: one self-contained HTML file per run, written
beside you, with the transcript and every request the proxy decided about.
No server, nothing to fetch, nothing to sign in to — you hand someone the
file. This is a real run, reformatted — Claude on a sealed Sprites box,
asked to fetch two URLs:

| Method | Host | Path | Verdict | Rule |
|---|---|---|---|---|
| POST | api.anthropic.com | /v1/messages | injected | anthropic |
| POST | api.anthropic.com | /api/event_logging/v2/batch | injected | anthropic |
| GET | example.com | / | passthrough | allow:example.com |
| CONNECT | pastebin.com | pastebin.com:443 | **denied** | — |

Those last two rows are the point. An agent holding your Stripe key tried to
reach a paste site and the cloud instance metadata endpoint, and you have a line
of evidence for both. A tool running on your laptop cannot produce that page,
because there is no chokepoint to produce it from.

## What it is not

- Not multi-tenant. No accounts, no roles, no hosted tier. One human, their
  tokens, their box.
- Not a place agents live. It runs a job and gives you the record.
- Not optimised to start fast. It is optimised to be safe to leave.

## Try it

```
mix escript.build

./airlock check priv/policies/example.yaml    # what a policy compiles to
./airlock broker priv/policies/example.yaml   # the proxy, and the log, live
```

`broker` prints a proxy URL. Point anything at it — `curl -x`, a shell with
`HTTPS_PROXY` set — and the rows appear as requests end. That path needs no
credentials at all and is the quickest way to see what the record looks
like.

A whole run needs a box and a broker the box can reach:

```
export SPRITES_TOKEN=...
ngrok tcp 14322                               # a raw TCP tunnel, not an HTTP one

./airlock run policy.yaml "fix the failing test" \
  --broker-host 4.tcp.ngrok.io:19482
```

The run prints a summary and writes `airlock-<run>.html` beside you. That
file is the record: open it, or send it to someone who was not there.

The broker is a listener the box dials *out* to, so it needs an address on
the box's network. An HTTP reverse proxy will not do — the proxy protocol
is `CONNECT` — and a tunnel puts the session token on the public internet,
which [`Airlock.Broker.Reachability`](lib/airlock/broker/reachability.ex)
warns about and explains. A box that cannot be sealed
(`--provider runner`) refuses to run unless you pass `--unsealed`.

## Built on

The nine [`managoat_*`](https://github.com/managoat) libraries, all Apache-2.0
on Hex:
[`sandbox`](https://hex.pm/packages/managoat_sandbox) (the machine, and
default-deny egress),
[`runtimes`](https://hex.pm/packages/managoat_runtimes) (claude, codex, gemini
and opencode, up and speaking ACP),
[`acp`](https://hex.pm/packages/managoat_acp) (the session, blocks, permissions,
usage, tracing),
[`broker`](https://hex.pm/packages/managoat_broker) (the egress proxy and the
request log) and
[`runner`](https://hex.pm/packages/managoat_runner) (your own machine as a
provider).

## Licence

Apache-2.0. See [LICENSE](LICENSE).
