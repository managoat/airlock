defmodule Airlock.RuntimeTest do
  @moduledoc """
  Step 5, where the credential stops travelling.

  The claim under test: what reaches the box is a placeholder, and the real
  value is nowhere in the environment the runtime is provisioned with.
  """

  use ExUnit.Case, async: true

  alias Airlock.Broker.Reachability
  alias Airlock.Runtime
  alias Managoat.Runtimes

  @real "sk-ant-api03-the-real-key"

  describe "credentials/1" do
    test "maps a policy's variable names onto the keys the runtimes read" do
      assert Runtime.credentials(%{"ANTHROPIC_API_KEY" => "PH-ANTHROPIC"}) ==
               %{anthropic_api_key: "PH-ANTHROPIC"}

      assert Runtime.credentials(%{"CLAUDE_CODE_OAUTH_TOKEN" => "PH-OAUTH"}) ==
               %{claude_code_oauth_token: "PH-OAUTH"}
    end

    test "carries both anthropic credentials, because the fallback needs both" do
      # `Claude.fall_back_to_api_key/2` swaps one for the other on a box that
      # is already running, so the session has to hold both from the start.
      credentials =
        Runtime.credentials(%{
          "CLAUDE_CODE_OAUTH_TOKEN" => "PH-OAUTH",
          "ANTHROPIC_API_KEY" => "PH-KEY"
        })

      assert credentials == %{claude_code_oauth_token: "PH-OAUTH", anthropic_api_key: "PH-KEY"}
    end

    test "opencode reaches Google under a different variable name than gemini does" do
      # The env var's name belongs to the runtime-and-provider pair, not to
      # the provider. Both land on the same credential key.
      assert Runtime.credentials(%{"GOOGLE_GENERATIVE_AI_API_KEY" => "PH-G"}) ==
               %{gemini_api_key: "PH-G"}
    end

    test "drops a variable no runtime delivers, rather than inventing a key" do
      # A policy names its own variables and the atom table is not garbage
      # collected, so this is a fixed table rather than String.to_atom/1.
      assert Runtime.credentials(%{"STRIPE_RESTRICTED_KEY" => "PH-STRIPE"}) == %{}
    end

    test "deliverable_vars/0 names what a policy can expect a runtime to deliver" do
      assert "ANTHROPIC_API_KEY" in Runtime.deliverable_vars()
      refute "STRIPE_RESTRICTED_KEY" in Runtime.deliverable_vars()
    end
  end

  describe "env/4 — the containment claim" do
    setup do
      {:ok, claude} = Runtimes.for_runtime("claude")

      box_env = %{
        "HTTPS_PROXY" => "http://mb_token:airlock@broker.example:14322",
        "ANTHROPIC_API_KEY" => "PLACEHOLDER-ANTHROPIC"
      }

      %{claude: claude, box_env: box_env}
    end

    test "the box is given the placeholder where the key would be", ctx do
      env =
        Runtime.env(ctx.claude, %{}, ctx.box_env, %{
          "ANTHROPIC_API_KEY" => "PLACEHOLDER-ANTHROPIC"
        })

      assert {"ANTHROPIC_API_KEY", "PLACEHOLDER-ANTHROPIC"} =
               List.keyfind(env, "ANTHROPIC_API_KEY", 0)

      refute Enum.any?(env, fn {_name, value} -> value == @real end)
      refute inspect(env) =~ @real
    end

    test "the proxy environment survives the runtime's own variables", ctx do
      env = Runtime.env(ctx.claude, %{}, ctx.box_env, %{"ANTHROPIC_API_KEY" => "PH"})

      assert {"HTTPS_PROXY", "http://mb_token:airlock@broker.example:14322"} =
               List.keyfind(env, "HTTPS_PROXY", 0)
    end

    test "credentials win over anything the box environment set for the same name", ctx do
      # Precedence goatherd settled, for the opposite payload: nothing
      # earlier may shadow the variable the run authenticates with.
      env = Runtime.env(ctx.claude, %{}, ctx.box_env, %{"ANTHROPIC_API_KEY" => "PH-FROM-POLICY"})

      assert {"ANTHROPIC_API_KEY", "PH-FROM-POLICY"} = List.keyfind(env, "ANTHROPIC_API_KEY", 0)
      assert Enum.count(env, &(elem(&1, 0) == "ANTHROPIC_API_KEY")) == 1
    end

    test "the optional callback is dispatched, not guarded away", ctx do
      # The trap: `function_exported?/3` is false for a module that is
      # merely not loaded, which in an escript is the normal state. Purging
      # the module first is the only way to test it — merely calling the
      # function loads it and the test passes either way.
      :code.purge(ctx.claude)
      :code.delete(ctx.claude)

      env = Runtime.env(ctx.claude, %{}, %{}, %{"ANTHROPIC_API_KEY" => "PH"})

      assert {"ANTHROPIC_API_KEY", "PH"} = List.keyfind(env, "ANTHROPIC_API_KEY", 0)
    end

    test "an oauth token is exported instead of an api key, never both", ctx do
      env =
        Runtime.env(ctx.claude, %{}, %{}, %{
          "CLAUDE_CODE_OAUTH_TOKEN" => "PH-OAUTH",
          "ANTHROPIC_API_KEY" => "PH-KEY"
        })

      # `Claude.default_env/2` picks exactly one: mixing them has picked the
      # wrong one depending on CLI version.
      assert {"CLAUDE_CODE_OAUTH_TOKEN", "PH-OAUTH"} =
               List.keyfind(env, "CLAUDE_CODE_OAUTH_TOKEN", 0)

      refute List.keyfind(env, "ANTHROPIC_API_KEY", 0)
    end
  end

  describe "reachability" do
    test "classifies what a box was given" do
      assert Reachability.classify("127.0.0.1:14322") == :loopback
      assert Reachability.classify("localhost") == :loopback
      assert Reachability.classify("[::1]:8443") == :loopback
      assert Reachability.classify("10.0.0.4") == :private
      assert Reachability.classify("192.168.1.9:14322") == :private
      assert Reachability.classify("172.16.0.1") == :private
      assert Reachability.classify("169.254.169.254") == :private
      assert Reachability.classify("4.tcp.ngrok.io:19482") == :public
      assert Reachability.classify("broker.example.com") == :public
    end

    test "a local box may use a loopback broker, which is the whole point of one" do
      assert :ok = Reachability.check("127.0.0.1:14322", :runner)
      assert :ok = Reachability.check("127.0.0.1:14322", :fake)
    end

    test "a cloud box may not" do
      assert {:error, {:unreachable_broker, _, :loopback, :sprites}} =
               Reachability.check("127.0.0.1:14322", :sprites)

      assert {:error, {:unreachable_broker, _, :private, :e2b}} =
               Reachability.check("10.0.0.4:14322", :e2b)
    end

    test "a cloud box with a reachable address is fine" do
      assert :ok = Reachability.check("4.tcp.ngrok.io:19482", :sprites)
    end

    test "a public hop warns that the session token rides in the clear" do
      # The broker's listener is plaintext — `Managoat.Broker`'s port option
      # is documented as such and there is no TLS option on it — so every
      # request carries Proxy-Authorization over the public internet.
      warning = Reachability.warning("4.tcp.ngrok.io:19482", :sprites)

      assert warning =~ "plaintext"
      assert warning =~ "Proxy-Authorization"
    end

    test "a local hop has nothing to warn about" do
      assert Reachability.warning("127.0.0.1:14322", :runner) == nil
      assert Reachability.warning("4.tcp.ngrok.io:19482", :runner) == nil
    end
  end
end
