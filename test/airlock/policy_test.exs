defmodule Airlock.PolicyTest do
  use ExUnit.Case, async: true

  alias Airlock.Policy
  alias Airlock.Policy.Credential

  @full """
  allow:
    - github.com
    - registry.npmjs.org
    - api.stripe.com
    - api.anthropic.com

  credentials:
    - host: api.stripe.com
      scheme: bearer
      from: env:STRIPE_RESTRICTED_KEY

    - host: api.anthropic.com
      scheme: substitute
      placeholder: "PLACEHOLDER-ANTHROPIC"
      from: env:ANTHROPIC_API_KEY

    - host: "github.com/managoat/*"
      scheme: basic
      username: x-access-token
      from: env:GITHUB_TOKEN

  unmatched: deny
  expires_in: "4h"
  """

  describe "parse/1" do
    test "reads the shape PLAN.md aims for" do
      assert {:ok, policy} = Policy.parse(@full)

      assert policy.allow == [
               "github.com",
               "registry.npmjs.org",
               "api.stripe.com",
               "api.anthropic.com"
             ]

      assert policy.unmatched == :deny
      assert policy.expires_in == 4 * 3600
      assert length(policy.credentials) == 3
    end

    test "keeps credentials a list, so one host can carry two" do
      # A run may need both a subscription token and an API key for
      # api.anthropic.com, because Claude.fall_back_to_api_key/2 swaps one
      # for the other on a box that is already running. Collapsing this to
      # a map on host would make that impossible to express.
      yaml = """
      allow: [api.anthropic.com]
      credentials:
        - host: api.anthropic.com
          name: anthropic-oauth
          scheme: substitute
          placeholder: "__AIRLOCK_OAUTH__"
          from: env:CLAUDE_CODE_OAUTH_TOKEN
        - host: api.anthropic.com
          name: anthropic-key
          scheme: substitute
          placeholder: "__AIRLOCK_API_KEY__"
          from: env:ANTHROPIC_API_KEY
      """

      assert {:ok, policy} = Policy.parse(yaml)
      assert Enum.map(policy.credentials, & &1.name) == ["anthropic-oauth", "anthropic-key"]
      assert Policy.required_vars(policy) == ["ANTHROPIC_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN"]
    end

    test "an empty file is a policy that denies everything" do
      assert {:ok, %Policy{allow: [], credentials: [], unmatched: :deny}} = Policy.parse("")
    end

    test "de-duplicates allow entries and keeps the author's order" do
      assert {:ok, policy} = Policy.parse("allow: [b.com, a.com, b.com]")
      assert policy.allow == ["b.com", "a.com"]
    end

    test "defaults unmatched to deny, which is the only value that makes allow mean anything" do
      assert {:ok, %Policy{unmatched: :deny}} = Policy.parse("allow: [a.com]")
    end

    test "accepts unmatched: passthrough, but only written down" do
      assert {:ok, %Policy{unmatched: :passthrough}} =
               Policy.parse("allow: [a.com]\nunmatched: passthrough")
    end

    test "a credential's name defaults to its host, so the egress log always names a rule" do
      assert {:ok, policy} =
               Policy.parse("""
               allow: [a.com]
               credentials:
                 - host: a.com
                   scheme: bearer
                   from: env:TOKEN
               """)

      assert [%Credential{name: "a.com"}] = policy.credentials
    end

    test "passthrough needs no from:" do
      assert {:ok, policy} =
               Policy.parse("""
               allow: [a.com]
               credentials:
                 - host: a.com
                   scheme: passthrough
               """)

      assert [%Credential{scheme: :passthrough, from: nil}] = policy.credentials
      assert Policy.required_vars(policy) == []
    end

    test "expires_in takes seconds, minutes, hours and days" do
      for {written, seconds} <- [{"90s", 90}, {"30m", 1800}, {"4h", 14_400}, {"1d", 86_400}] do
        assert {:ok, %Policy{expires_in: ^seconds}} =
                 Policy.parse("expires_in: \"#{written}\"")
      end
    end
  end

  describe "parse/1 refuses what would otherwise be a wrong answer" do
    test "an unknown top-level key" do
      # `allowed:` instead of `allow:` leaves an empty allow list, which is
      # a legal policy meaning deny-everything — so the typo would read as
      # a deliberate lockdown rather than a mistake.
      assert {:error, {:unknown_keys, :policy, ["allowed"], _}} =
               Policy.parse("allowed: [github.com]")
    end

    test "an unknown key in a credential" do
      assert {:error, {:unknown_keys, {:credential, 0}, ["placehodler"], _}} =
               Policy.parse("""
               allow: [a.com]
               credentials:
                 - host: a.com
                   scheme: substitute
                   placehodler: "__X__"
                   from: env:T
               """)
    end

    test "a credential naming a host allow does not cover" do
      assert {:error, {:credential_not_allowed, "api.stripe.com"}} =
               Policy.parse("""
               allow: [github.com]
               credentials:
                 - host: api.stripe.com
                   scheme: bearer
                   from: env:STRIPE_RESTRICTED_KEY
               """)
    end

    test "a placeholder the broker itself would refuse" do
      # Validated where the policy is written rather than on every request
      # that matches it, which is what Managoat.Broker.Rule asks a host to
      # do. "id" would rewrite every `id` in every matching path.
      assert {:error, {:bad_placeholder, 0, "id"}} =
               Policy.parse("""
               allow: [a.com]
               credentials:
                 - host: a.com
                   scheme: substitute
                   placeholder: "id"
                   from: env:T
               """)
    end

    test "a basic credential with no username" do
      assert {:error, {:missing_key, {:credential, 0}, "username"}} =
               Policy.parse("""
               allow: [github.com]
               credentials:
                 - host: github.com
                   scheme: basic
                   from: env:GITHUB_TOKEN
               """)
    end

    test "a substitute credential with no placeholder" do
      assert {:error, {:missing_key, {:credential, 0}, "placeholder"}} =
               Policy.parse("""
               allow: [a.com]
               credentials:
                 - host: a.com
                   scheme: substitute
                   from: env:T
               """)
    end

    test "the custom scheme, which is not built, by name" do
      assert {:error, {:scheme_not_built, 0, "custom"}} =
               Policy.parse("""
               allow: [a.com]
               credentials:
                 - host: a.com
                   scheme: custom
                   from: env:T
               """)
    end

    test "a scheme that does not exist" do
      assert {:error, {:bad_scheme, 0, "oauth", _}} =
               Policy.parse("""
               allow: [a.com]
               credentials:
                 - host: a.com
                   scheme: oauth
                   from: env:T
               """)
    end

    test "a from: that is not a reference" do
      assert {:error, {:bad_from, 0, "sk-live-actually-a-secret"}} =
               Policy.parse("""
               allow: [a.com]
               credentials:
                 - host: a.com
                   scheme: bearer
                   from: sk-live-actually-a-secret
               """)
    end

    test "an expires_in nobody can read" do
      assert {:error, {:bad_expires_in, "4 hours"}} = Policy.parse(~s(expires_in: "4 hours"))
      assert {:error, {:bad_expires_in, "0h"}} = Policy.parse(~s(expires_in: "0h"))
    end

    test "an unmatched that is neither" do
      assert {:error, {:bad_unmatched, "allow"}} = Policy.parse("unmatched: allow")
    end

    test "a top level that is not a mapping" do
      assert {:error, {:not_a_mapping, _}} = Policy.parse("- github.com")
    end

    test "malformed YAML, with the parser's own message" do
      assert {:error, {:malformed_yaml, _message}} = Policy.parse("allow: b\n  credentials: c")
    end

    @tag timeout: 30_000
    test "YAML that does not come back is given up on rather than hung on" do
      # `YamlElixir.read_from_string/1` on an unclosed flow sequence spins
      # inside yamerl indefinitely instead of returning an error. Unbounded,
      # a typo in a policy file hangs airlock with no output; the parse is
      # bounded for exactly this input.
      assert {:error, {:yaml_timeout, _ms}} = Policy.parse("allow: [a.com\ncredentials:")
    end
  end

  describe "coverage" do
    test "a path-scoped credential is covered by its host" do
      assert Credential.covered_by?(credential("github.com/managoat/*"), ["github.com"])
    end

    test "a port-pinned credential is covered by its host" do
      assert Credential.covered_by?(credential("api.internal:8443"), ["api.internal"])
    end

    test "a wildcard allow entry covers a subdomain credential" do
      assert Credential.covered_by?(credential("api.example.com"), ["*.example.com"])
    end

    test "a wildcard allow entry does not cover the apex, as the library says" do
      refute Credential.covered_by?(credential("example.com"), ["*.example.com"])
    end

    test "a wildcard credential needs the same wildcard allowed" do
      assert Credential.covered_by?(credential("*.example.com"), ["*.example.com"])
      refute Credential.covered_by?(credential("*.example.com"), ["api.example.com"])
    end

    test "matching is case-insensitive on the host" do
      assert Credential.covered_by?(credential("API.Stripe.com"), ["api.stripe.com"])
    end
  end

  describe "the struct cannot hold a secret" do
    test "from: is a reference, and nothing resolves it here" do
      System.put_env("AIRLOCK_TEST_SECRET", "sk-live-do-not-print-me")
      on_exit(fn -> System.delete_env("AIRLOCK_TEST_SECRET") end)

      assert {:ok, policy} =
               Policy.parse("""
               allow: [a.com]
               credentials:
                 - host: a.com
                   scheme: bearer
                   from: env:AIRLOCK_TEST_SECRET
               """)

      assert [%Credential{from: {:env, "AIRLOCK_TEST_SECRET"}}] = policy.credentials

      # The whole point: a policy is a thing a user checks in and a record
      # is a thing they hand someone, and both get printed.
      refute inspect(policy, limit: :infinity) =~ "sk-live-do-not-print-me"
    end
  end

  describe "load/1" do
    test "names the file it could not read" do
      assert {:error, {:unreadable, "/nope/policy.yaml", :enoent}} =
               Policy.load("/nope/policy.yaml")
    end

    test "reads the checked-in example" do
      assert {:ok, %Policy{}} = Policy.load("priv/policies/example.yaml")
    end
  end

  defp credential(host) do
    %Credential{name: host, host: host, scheme: :bearer, from: {:env, "T"}}
  end
end
