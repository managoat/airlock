# Airlock

Run a coding agent on a machine you chose, with credentials that machine never
holds, and get a record of everything it did.

> **Status: design only.** Nothing is built yet. This repository currently
> holds the brief ([CLAUDE.md](CLAUDE.md)) and the build plan
> ([PLAN.md](PLAN.md)).

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

Then you get the record:

| Method | Host | Path | Verdict | Rule |
|---|---|---|---|---|
| POST | api.anthropic.com | /v1/messages | injected | anthropic |
| GET | registry.npmjs.org | /stripe | passthrough | — |
| POST | api.stripe.com | /v1/customers | injected | stripe |
| GET | pastebin.com | /raw/x9f2 | **denied** | unmatched |
| GET | 169.254.169.254 | /latest/meta-data/ | **denied** | unmatched |

Those last two rows are the point. An agent holding your Stripe key tried to
reach a paste site and the cloud instance metadata endpoint, and you have a line
of evidence for both. A tool running on your laptop cannot produce that page,
because there is no chokepoint to produce it from.

## What it is not

- Not multi-tenant. No accounts, no roles, no hosted tier. One human, their
  tokens, their box.
- Not a place agents live. It runs a job and gives you the record.
- Not optimised to start fast. It is optimised to be safe to leave.

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
