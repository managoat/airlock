# Airlock

Run a coding agent in a sealed sandbox without putting real credentials on the
machine.

Airlock routes the sandbox's outbound traffic through a default-deny proxy. The
agent receives placeholders; the proxy adds or substitutes credentials only for
destinations named in policy. After the run, Airlock destroys the sandbox and
writes a self-contained HTML record containing the transcript, egress decisions,
tool calls, and filesystem changes.

> **Status:** early prototype. The Claude + Sprites path and HTML records work
> end to end. Airlock cannot yet reattach after the CLI exits, and Sprites is the
> only cloud provider wired up.

## How it works

1. A YAML policy defines every reachable host and where credentials may go.
2. Airlock provisions a fresh sandbox, installs the agent, and seals egress to
   the broker.
3. The broker allows or denies each request and injects credentials only when a
   rule matches.
4. Airlock writes `airlock-<run>.html` and destroys the sandbox.

Denied requests are part of the record, including traffic the agent or its
harness attempted without mentioning it in the transcript.

## Build

Airlock requires Elixir 1.18 or later.

```sh
mix deps.get
mix escript.build
./airlock check priv/policies/example.yaml
```

`check` parses a policy, shows the compiled network and credential rules, and
reports missing environment variables.

## Policy

```yaml
allow:
  - api.anthropic.com
  - example.com

credentials:
  - host: api.anthropic.com
    scheme: substitute
    placeholder: PLACEHOLDER-ANTHROPIC
    from: env:ANTHROPIC_API_KEY

unmatched: deny
```

See [`priv/policies/example.yaml`](priv/policies/example.yaml) for bearer, basic,
and path-scoped credential rules.

## Run

A cloud sandbox must be able to reach the local broker. For a development run,
bind the broker to a known port and expose that port with a raw TCP tunnel:

```sh
export SPRITES_TOKEN=...
export ANTHROPIC_API_KEY=...

ngrok tcp 14322

./airlock run policy.yaml "fetch https://example.com" \
  --broker-port 14322 \
  --broker-host 4.tcp.ngrok.io:19482
```

Replace `--broker-host` with the address printed by ngrok. An HTTP tunnel will
not work because the broker handles `CONNECT` traffic.

> **Security:** the broker connection is currently plaintext, so a public tunnel
> exposes its session token in transit. Treat tunneling as a development setup
> and use short-lived, narrowly scoped credentials.

The default tool-permission mode is `ask`. Because no human is attached to
answer, requests are denied and recorded; pass `--permissions auto_allow` for an
unattended run that may use tools.

If the CLI is killed before cleanup, the sandbox may survive:

```sh
./airlock boxes
./airlock reap --yes
```

`reap` destroys every Airlock-created box in the selected provider account.

Run `./airlock help` for all runtimes, providers, and options.

## Project docs

- [`CLAUDE.md`](CLAUDE.md) — product and architecture brief
- [`PLAN.md`](PLAN.md) — milestones and design decisions
- [`NOTES-M0.md`](NOTES-M0.md) and [`NOTES-M2.md`](NOTES-M2.md) — implementation
  findings

## License

Apache-2.0. See [`LICENSE`](LICENSE).
