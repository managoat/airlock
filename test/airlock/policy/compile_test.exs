defmodule Airlock.Policy.CompileTest do
  use ExUnit.Case, async: true

  alias Airlock.Policy
  alias Airlock.Policy.Compile
  alias Managoat.Broker.Injector
  alias Managoat.Broker.Rule
  alias Managoat.Sandbox.NetworkPolicy

  @policy """
  allow:
    - github.com
    - registry.npmjs.org
    - api.stripe.com
    - api.anthropic.com

  credentials:
    - host: api.stripe.com
      name: stripe
      scheme: bearer
      from: env:STRIPE_KEY

    - host: api.anthropic.com
      name: anthropic
      scheme: substitute
      placeholder: "PLACEHOLDER-ANTHROPIC"
      from: env:ANTHROPIC_API_KEY

    - host: "github.com/managoat/*"
      name: github
      scheme: basic
      username: x-access-token
      from: env:GITHUB_TOKEN
  """

  @vars %{
    "STRIPE_KEY" => "sk_test_stripe",
    "ANTHROPIC_API_KEY" => "sk-ant-real",
    "GITHUB_TOKEN" => "ghp_real"
  }

  setup do
    {:ok, policy} = Policy.parse(@policy)
    %{policy: policy}
  end

  describe "network_policy/2 — the box's layer" do
    test "names the broker and nothing else", %{policy: policy} do
      # The whole two-layer answer. A box that may reach github.com
      # *directly* can reach it without the proxy — anything that drops
      # HTTPS_PROXY (sudo, npm 9) egresses to an allowed host unbrokered
      # and therefore unrecorded, and the record would show nothing while
      # nothing failed. With one destination the chokepoint is structural.
      assert %NetworkPolicy{allow: ["127.0.0.1"]} =
               Compile.network_policy(policy, "127.0.0.1:14322")
    end

    test "does not repeat the allow list", %{policy: policy} do
      %NetworkPolicy{allow: allow} = Compile.network_policy(policy, "broker.local")
      refute "github.com" in allow
      refute "api.stripe.com" in allow
    end

    test "a policy that allows nothing still reaches the broker" do
      # `NetworkPolicy` with `allow: []` means deny everything, so the
      # broker's own address is what keeps a no-egress job able to be
      # denied *at the proxy*, where the denial becomes a row.
      {:ok, policy} = Policy.parse("allow: []")

      assert %NetworkPolicy{allow: ["broker.local"]} =
               Compile.network_policy(policy, "broker.local")
    end
  end

  describe "the port is stripped from the egress policy" do
    test "because NetworkPolicy's allow is domains, not authorities", %{policy: policy} do
      # A `host:port` in that list matches nothing, so the box is sealed
      # away from the one destination it is meant to have — and it fails
      # silently: the seal reports :ok and the agent then cannot connect to
      # anything. The first real Sprites run died here.
      assert %NetworkPolicy{allow: ["4.tcp.ngrok.io"]} =
               Compile.network_policy(policy, "4.tcp.ngrok.io:12171")
    end

    test "a bare host is unchanged", %{policy: policy} do
      assert %NetworkPolicy{allow: ["broker.example"]} =
               Compile.network_policy(policy, "broker.example")
    end

    test "a bracketed IPv6 literal keeps its brackets and loses its port", %{policy: policy} do
      assert %NetworkPolicy{allow: ["[::1]"]} = Compile.network_policy(policy, "[::1]:14322")
    end
  end

  describe "rules/2 — the proxy's layer" do
    test "credential rules first, in the policy's order, then one passthrough per allowed host",
         %{policy: policy} do
      assert {:ok, rules} = Compile.rules(policy, @vars)

      assert Enum.map(rules, & &1.name) == [
               "stripe",
               "anthropic",
               "github",
               "allow:github.com",
               "allow:registry.npmjs.org",
               "allow:api.stripe.com",
               "allow:api.anthropic.com"
             ]
    end

    test "resolves each scheme into the shape the library asks for", %{policy: policy} do
      assert {:ok, rules} = Compile.rules(policy, @vars)

      assert %Rule{scheme: :bearer, credential: "sk_test_stripe"} = by_name(rules, "stripe")

      assert %Rule{
               scheme: :substitute,
               credential: "sk-ant-real",
               placeholder: "PLACEHOLDER-ANTHROPIC"
             } = by_name(rules, "anthropic")

      # :basic takes a {username, password} pair, which is why the policy
      # has to name the username.
      assert %Rule{scheme: :basic, credential: {"x-access-token", "ghp_real"}} =
               by_name(rules, "github")
    end

    test "an api_key rule defaults to Authorization with no prefix" do
      {:ok, policy} =
        Policy.parse("""
        allow: [generativelanguage.googleapis.com]
        credentials:
          - host: generativelanguage.googleapis.com
            name: gemini
            scheme: api_key
            header: x-goog-api-key
            from: env:GEMINI_API_KEY
        """)

      # Gemini's key is header-only — `x-goog-api-key`, never `?key=` in
      # the query. The policy names the header rather than the code
      # knowing about Gemini.
      assert {:ok, [rule | _]} = Compile.rules(policy, %{"GEMINI_API_KEY" => "k"})
      assert %Rule{scheme: :api_key, header: "x-goog-api-key", prefix: "", credential: "k"} = rule
    end

    test "reports every missing variable at once, not the first", %{policy: policy} do
      assert {:error, {:missing_vars, missing}} = Compile.rules(policy, %{})
      assert missing == ["ANTHROPIC_API_KEY", "GITHUB_TOKEN", "STRIPE_KEY"]
    end

    test "a passthrough credential compiles to a rule with no credential" do
      {:ok, policy} =
        Policy.parse("""
        allow: [example.com]
        credentials:
          - host: example.com
            name: explicit
            scheme: passthrough
        """)

      assert {:ok, [rule | _]} = Compile.rules(policy, %{})
      assert %Rule{name: "explicit", scheme: :passthrough, credential: nil} = rule
    end
  end

  describe "the two layers agree" do
    test "every allowed host has a rule that lets it through", %{policy: policy} do
      # `unmatched_host_policy: :deny` refuses a host no rule names, so an
      # allowed host with no rule would be denied — the allow list saying
      # one thing and the proxy doing another.
      assert {:ok, rules} = Compile.rules(policy, @vars)

      for host <- policy.allow do
        assert Enum.any?(rules, &Injector.host_matches?(&1.pattern, host, 443)),
               "no rule matches the allowed host #{host}"
      end
    end

    test "a host reachable only under a path still reaches the host", %{policy: policy} do
      # `github.com/managoat/*` attaches the token on that path only. A
      # request to github.com/elsewhere matches no credential rule, and
      # under deny it would be refused — but `allow: [github.com]` said the
      # host is reachable. The passthrough rule is what makes that true.
      assert {:ok, rules} = Compile.rules(policy, @vars)

      matching =
        Enum.filter(rules, &Injector.matches?(&1.pattern, "github.com", 443, "/elsewhere"))

      assert Enum.map(matching, & &1.name) == ["allow:github.com"]
    end

    test "the passthrough rule does not cost an injecting rule its credential", %{policy: policy} do
      # Broker 0.7.0 pins this: `:passthrough` never displaces a rule that
      # injects, however specific it is. It is why a passthrough can be
      # emitted for every allowed host rather than only the uncovered ones.
      assert {:ok, rules} = Compile.rules(policy, @vars)

      matching =
        Enum.filter(rules, &Injector.matches?(&1.pattern, "api.stripe.com", 443, "/v1/customers"))

      assert Enum.map(matching, & &1.name) == ["stripe", "allow:api.stripe.com"]
    end
  end

  describe "placeholders/1" do
    test "is every substitute entry, not the one provisioning chose", %{policy: policy} do
      assert Compile.placeholders(policy) == %{
               "ANTHROPIC_API_KEY" => "PLACEHOLDER-ANTHROPIC"
             }
    end

    test "carries both anthropic credentials, because the fallback needs both" do
      # Claude.fall_back_to_api_key/2 swaps an OAuth token for an API key
      # on a box that is already running, so a session minted with only the
      # first placeholder cannot serve the second.
      {:ok, policy} =
        Policy.parse("""
        allow: [api.anthropic.com]
        credentials:
          - host: api.anthropic.com
            scheme: substitute
            placeholder: "__AIRLOCK_OAUTH__"
            from: env:CLAUDE_CODE_OAUTH_TOKEN
          - host: api.anthropic.com
            scheme: substitute
            placeholder: "__AIRLOCK_API_KEY__"
            from: env:ANTHROPIC_API_KEY
        """)

      assert Compile.placeholders(policy) == %{
               "CLAUDE_CODE_OAUTH_TOKEN" => "__AIRLOCK_OAUTH__",
               "ANTHROPIC_API_KEY" => "__AIRLOCK_API_KEY__"
             }
    end

    test "holds no credential values", %{policy: policy} do
      refute policy |> Compile.placeholders() |> inspect() =~ "sk-ant-real"
    end
  end

  defp by_name(rules, name), do: Enum.find(rules, &(&1.name == name))
end
