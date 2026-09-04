defmodule Airlock.Policy.Compile do
  @moduledoc """
  A policy onto the two layers that enforce it.

  `PLAN.md` says to work out what `allow` compiles to on both layers
  before writing either, because it is the first place the two-layer design
  gets tested for real. This is that answer.

  ## The answer: `allow` compiles onto the broker, not onto the box

      NetworkPolicy{allow: [broker_host]}          # the box: one way out
      [credential rules] ++ [passthrough rules]    # the proxy: which hosts, and with what

  The box's egress policy names **the broker and nothing else**. Every host
  in `allow` becomes a `:passthrough` rule at the proxy instead, and the
  session's `unmatched_host_policy` is `:deny`, so a host the policy does
  not name is refused there.

  ## Why not `allow ++ [broker]` on the box

  That is the obvious reading — belt and braces, the box's own egress
  policy repeating the allow list — and it is weaker, not stronger.

  Airlock's claim is that *every* outbound request is logged with the
  verdict and the rule that decided it. A box that may reach `github.com`
  directly can reach it without the proxy: anything that ignores
  `HTTPS_PROXY` — and `CLAUDE.md` already records two of those, `sudo`
  stripping the proxy environment and npm 9 sending no proxy credentials —
  egresses to an allowed host unbrokered and therefore **unrecorded**. The
  record would show nothing and nothing would have failed. Repeating the
  allow list on the box buys defence in depth against a threat that is not
  the one this product has (a host outside the list), and pays for it by
  opening a hole in the one guarantee it sells.

  With `allow: [broker_host]` the chokepoint is structural: an agent that
  drops the proxy environment does not reach `github.com` unlogged, it
  fails to reach anything, which is a loud failure rather than a silent
  gap in the evidence.

  It also means the box never resolves an allowed host's name. A client
  going through a proxy sends `CONNECT github.com:443` and lets the proxy
  resolve it, so the box needs no DNS for anything but the broker — and
  when the broker is an address, none at all.

  ## Why a `:passthrough` rule for *every* allow entry

  Including hosts that also have a credential rule. Two reasons, both from
  `Managoat.Broker.Rule`:

    * a credential rule may be narrower than the host. `github.com/managoat/*`
      attaches a token on that path; a request to `github.com/elsewhere`
      matches no credential rule, and under `unmatched_host_policy: :deny`
      it would be refused — but `allow: [github.com]` said the host is
      reachable. The passthrough rule is what makes `allow` mean what it
      says, with the credential attaching only where it was scoped to;
    * it is safe to add. Broker 0.7.0 pins that "`:passthrough` never
      displaces a rule that injects, however specific it is" — it is how a
      host is allowed under `deny`, not a way to suppress injection. So a
      passthrough for `api.stripe.com` cannot cost that host its bearer
      token, and the library has a test holding that.

  ## Rule order

  Broker **0.7.0 changed this**, and `CLAUDE.md` and `PLAN.md` both still
  describe the old contract ("the first matched rule that sets a header
  wins"). Since 0.7.0 the **most specific** matched rule sets the header:
  exact host over wildcard, then a pinned port, then the longest literal
  path prefix, and declaration order only breaks what is left.

  Two consequences here. Credential rules are emitted in the order the
  policy wrote them, so equally-specific rules still resolve by the
  author's order. And the passthrough rules can safely go last, where
  under declaration order they would have shadowed everything.

  ## `allow_private_upstreams` stays `false`

  `CLAUDE.md` flags the local-runner path as "exactly the private-upstream
  case" and says to think it through rather than flip the flag. Thinking it
  through: the flag governs which **upstreams the proxy may dial**, and the
  box-to-proxy connection is not an upstream. A box on the same machine
  dials the broker's listener as a client; the origins the broker then
  dials on its behalf are `api.stripe.com` and friends, which are public.
  So the flag is not implicated by the local box at all and stays `false`,
  where it belongs — with it `true`, a policy allowing a host that resolves
  to `169.254.169.254` would be dialled.

  A test rig with a local origin is the real case for it, and
  `Airlock.Broker.start_link/1` takes it as an option for exactly that,
  defaulting to `false`.
  """

  alias Airlock.Policy
  alias Airlock.Policy.Credential
  alias Managoat.Broker.Rule
  alias Managoat.Sandbox.NetworkPolicy

  @doc """
  The box's egress policy: the broker's host, and nothing else.

  `broker_host` is the host the box addresses the broker by — a name it can
  resolve or a literal address. Everything the policy allows is reached
  *through* it; see the moduledoc for why the allow list is not repeated
  here.
  """
  @spec network_policy(Policy.t(), String.t()) :: NetworkPolicy.t()
  def network_policy(%Policy{}, broker_host) when is_binary(broker_host) do
    %NetworkPolicy{allow: [broker_host]}
  end

  @doc """
  The proxy's rules: the policy's credentials with their references
  resolved, then a `:passthrough` rule per allowed host.

  `vars` is the variable map a `from: env:NAME` reference resolves against.
  Every missing name is reported together rather than one per attempt, so a
  user with three unset variables learns all three at once.

  A `:passthrough` credential entry resolves to a rule with no credential,
  which is what that scheme is.
  """
  @spec rules(Policy.t(), %{optional(String.t()) => String.t()}) ::
          {:ok, [Rule.t()]} | {:error, {:missing_vars, [String.t()]}}
  def rules(%Policy{} = policy, vars) when is_map(vars) do
    case missing_vars(policy, vars) do
      [] -> {:ok, Enum.map(policy.credentials, &rule(&1, vars)) ++ passthrough_rules(policy)}
      missing -> {:error, {:missing_vars, missing}}
    end
  end

  @doc """
  The placeholders the box is handed in place of real credentials.

  A map of variable name to placeholder, for every `:substitute` entry —
  the environment a runtime is provisioned with, and the reason a
  placeholder lifted off the box's disk is worth nothing anywhere else.

  It carries **every** `:substitute` entry the policy declares, not the one
  provisioning happened to choose. `Airlock.Policy.Credential` says why:
  `Managoat.Runtimes.Claude.fall_back_to_api_key/2` can swap an OAuth token
  for an API key on a box that is already running, and a session minted
  with only the first placeholder cannot serve the second.
  """
  @spec placeholders(Policy.t()) :: %{optional(String.t()) => String.t()}
  def placeholders(%Policy{credentials: credentials}) do
    for %Credential{scheme: :substitute, from: {:env, name}, placeholder: placeholder} <-
          credentials,
        into: %{},
        do: {name, placeholder}
  end

  @doc """
  Each rule's name to its scheme, without resolving a credential.

  `Airlock.Egress` needs this to render a verdict, and the reason is a
  sharp edge in the library that reads backwards.

  The request event's `outcome` is `:injected` whenever **a rule matched**
  and `:passthrough` only when **none did** and the session let the request
  through anyway — so `:passthrough` is reachable only under
  `unmatched_host_policy: :passthrough`. Under `:deny`, which is the whole
  of Airlock's stance, every request that is not denied reports
  `:injected`, including one that matched a `:passthrough` rule and had
  nothing attached to it at all.

  The event carries the rule's *name* but not its scheme, and this compiler
  is what named the rules, so this is where the two can be put back
  together. `Airlock.Egress` uses it to say `passthrough` for a request
  that was let through untouched — which is what the reader of a record
  needs to be told, and what the raw `outcome` would get wrong.
  """
  @spec rule_schemes(Policy.t()) :: %{optional(String.t()) => Managoat.Broker.Rule.scheme()}
  def rule_schemes(%Policy{} = policy) do
    from_credentials = for c <- policy.credentials, into: %{}, do: {c.name, c.scheme}
    from_allow = for host <- policy.allow, into: %{}, do: {"allow:#{host}", :passthrough}

    Map.merge(from_allow, from_credentials)
  end

  # ── one rule ───────────────────────────────────────────────────────────────

  defp rule(%Credential{scheme: :passthrough} = credential, _vars) do
    %Rule{name: credential.name, pattern: credential.host, scheme: :passthrough}
  end

  defp rule(%Credential{scheme: :basic} = credential, vars) do
    %Rule{
      name: credential.name,
      pattern: credential.host,
      scheme: :basic,
      credential: {credential.username, value(credential, vars)}
    }
  end

  defp rule(%Credential{scheme: :api_key} = credential, vars) do
    %Rule{
      name: credential.name,
      pattern: credential.host,
      scheme: :api_key,
      credential: value(credential, vars),
      header: credential.header || "Authorization",
      prefix: credential.prefix
    }
  end

  defp rule(%Credential{scheme: :substitute} = credential, vars) do
    %Rule{
      name: credential.name,
      pattern: credential.host,
      scheme: :substitute,
      credential: value(credential, vars),
      placeholder: credential.placeholder
    }
  end

  defp rule(%Credential{scheme: :bearer} = credential, vars) do
    %Rule{
      name: credential.name,
      pattern: credential.host,
      scheme: :bearer,
      credential: value(credential, vars)
    }
  end

  defp value(%Credential{from: {:env, name}}, vars), do: Map.fetch!(vars, name)

  # ── the allow list ─────────────────────────────────────────────────────────

  # Named `allow:<host>` so the egress log's Rule column says why a request
  # was let through, and says it in the policy's own vocabulary: a reader
  # can find the line in the file. A rule with a nil name would show `—`,
  # which is indistinguishable from a request nothing matched.
  defp passthrough_rules(%Policy{allow: allow}) do
    for host <- allow, do: %Rule{name: "allow:#{host}", pattern: host, scheme: :passthrough}
  end

  defp missing_vars(%Policy{} = policy, vars) do
    policy |> Policy.required_vars() |> Enum.reject(&Map.has_key?(vars, &1))
  end
end
