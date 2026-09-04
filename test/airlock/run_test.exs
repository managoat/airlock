defmodule Airlock.RunTest do
  @moduledoc """
  M0 steps 4–9, on the boxes that can be reached without a cloud account.

  The provider is `Managoat.Sandbox.Fake`, which is a real adapter — its
  commands are processes emitting real owner messages, and it advertises
  `:network_policy`, so **the seal actually happens here** and
  `Fake.policy/1` says what it was. `PLAN.md` calls the seal "the step with
  no prior art ... the part worth a test", and this is that test.

  What a fake box cannot do is *be* an agent — nothing on it speaks ACP —
  so a whole `Run.start/1` reaches the turn and fails there. That is the
  honest outcome and these tests assert it: every stage up to and including
  the seal is real, the policy the seal applied is readable back off the
  box, and the turn itself is driven separately against
  `Managoat.ACP.Testing.ScriptedAgent` through `Run.drive/2`.
  """

  use ExUnit.Case, async: false

  alias Airlock.Box
  alias Airlock.Box.Host
  alias Airlock.Policy
  alias Airlock.Run
  alias Airlock.Test.FakeBox
  alias Airlock.Test.UnsealableBox
  alias Airlock.Transcript
  alias Managoat.ACP.Peer
  alias Managoat.ACP.Testing.ScriptedAgent
  alias Managoat.Sandbox
  alias Managoat.Sandbox.Fake
  alias Managoat.Sandbox.NetworkPolicy

  @vars %{"STRIPE_KEY" => "sk_test_not_real", "ANTHROPIC_API_KEY" => "sk-ant-not-real"}

  setup do
    Fake.reset()
    Host.configure()

    # Neither fake is in the default adapter map; registering one is the
    # same job `Box.Host.configure/0` does for the runner.
    adapters = Sandbox.adapters()

    Application.put_env(
      :managoat_sandbox,
      :adapters,
      adapters
      |> Map.put(:fake, Fake)
      |> Map.put(:fake_box, FakeBox)
      |> Map.put(:unsealable, UnsealableBox)
    )

    on_exit(fn -> Application.put_env(:managoat_sandbox, :adapters, adapters) end)

    {:ok, policy} =
      Policy.parse("""
      allow:
        - api.stripe.com
        - api.anthropic.com
        - registry.npmjs.org

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

      unmatched: deny
      expires_in: "1h"
      """)

    %{policy: policy}
  end

  describe "the ordering" do
    test "packages and the runtime install before the seal, and destroy is last", %{
      policy: policy
    } do
      # The one constraint that cannot move. apt cannot reach the archives
      # once egress is default-deny, and `Managoat.Runtimes.ACP.install/3`
      # runs `npm install -g` — its own moduledoc names the exposure. So a
      # seal that drifted earlier would fail provisioning, and one that
      # drifted later would leave the box open while the agent worked.
      #
      # `trust` is before `runtime` for a different reason: without the
      # broker's root the box cannot complete a TLS handshake through it at
      # all, which is how the first real run against Sprites failed.
      # The turn fails: nothing on a fake box speaks ACP. Everything before
      # it is real, and the order is what is under test.
      assert {:error, _turn} = run(policy, stages: self())

      # `baseline` is between the seal and the turn: it is the state the
      # diff is against, so everything provisioning wrote has to be in it
      # rather than reading as the agent's work. `changes` is not here
      # because the turn failed, and a fake box has no diff to take.
      assert stages() == [
               "create",
               "packages",
               "trust",
               "runtime",
               "seal",
               "baseline",
               "turn",
               "destroy"
             ]
    end

    test "the box is destroyed even when the turn fails", %{policy: policy} do
      # A box that outlived a failed run is a box holding a placeholder and
      # a live proxy address. Settled question 4 says per-job, and per-job
      # has to mean per-job on the unhappy path too.
      assert {:error, _reason} = run(policy, stages: self())

      assert "destroy" in stages()
    end
  end

  describe "the seal" do
    test "applies exactly the broker's address, and nothing the policy allows", %{policy: policy} do
      assert {:error, _turn} = run(policy, stages: self(), broker_host: "broker.example:14322")

      # The seal really happened, and this is read back off the box rather
      # than off the struct that asked for it. The two-layer answer,
      # observed: allowed hosts are reached *through* the broker, so they
      # are rules at the proxy and not destinations on the box.
      assert "seal" in stages()

      # Captured while the turn was running, because the box is destroyed
      # at the end of the run and the Fake's state goes with it. That is
      # the claim worth pinning: the policy was in force *while the agent
      # worked*, not merely applied at some point.
      #
      # The port is gone: `allow` is domains, not authorities.
      assert_received {:policies, [%NetworkPolicy{allow: ["broker.example"]}]}
    end

    test "a provider that cannot be sealed stops the run", %{policy: policy} do
      # `Managoat.Runner.Adapter` refuses `apply_network_policy/2`, and
      # `Airlock.Test.UnsealableBox` refuses it the same way. A run that
      # believed it was contained and was not would produce a record that
      # is evidence of the wrong thing, so it stops instead.
      assert {:error, {:cannot_seal, :unsealable}} =
               Run.start(
                 policy: policy,
                 prompt: "hello",
                 provider: :unsealable,
                 broker_host: "broker.example:14322",
                 vars: @vars,
                 broker_name: unique_name()
               )
    end

    test "unsealed: true is the only way past it", %{policy: policy} do
      # Past the refusal, and on to the turn — which fails, because nothing
      # on a fake box speaks ACP. The point is only that the seal no longer
      # stopped it.
      assert {:error, reason} =
               Run.start(
                 policy: policy,
                 prompt: "hello",
                 provider: :unsealable,
                 unsealed: true,
                 broker_host: "broker.example:14322",
                 vars: @vars,
                 broker_name: unique_name(),
                 timeout: 2_000
               )

      refute match?({:cannot_seal, _}, reason)
    end

    test "sealable?/1 asks the adapter rather than a hardcoded list" do
      assert Box.sealable?(:fake_box)
      assert Box.sealable?(:sprites)
      refute Box.sealable?(:runner)
    end
  end

  describe "reachability is checked before anything is created" do
    test "a cloud box pointed at loopback is refused up front", %{policy: policy} do
      # Left to fail on its own this fails *after* provisioning, after npm,
      # after the seal — and it fails as an agent that made no requests,
      # which is indistinguishable from an agent that made none.
      assert {:error, {:unreachable_broker, _host, :loopback, :sprites}} =
               Run.start(
                 policy: policy,
                 prompt: "hello",
                 provider: :sprites,
                 broker_host: "127.0.0.1:14322",
                 vars: @vars,
                 broker_name: unique_name()
               )

      # Nothing was created: the check runs before the box exists.
      assert {:ok, names} = Sandbox.list_all_names(:fake_box)
      assert MapSet.size(names) == 0
    end

    test "an unknown runtime is refused before anything is created", %{policy: policy} do
      assert {:error, {:unknown_runtime, "gpt5", _supported}} =
               Run.start(
                 policy: policy,
                 prompt: "hello",
                 runtime: "gpt5",
                 provider: :fake_box,
                 vars: @vars,
                 broker_name: unique_name()
               )
    end
  end

  describe "the turn" do
    test "collects blocks, the session id and the stop reason" do
      {:ok, agent} =
        ScriptedAgent.start_link(
          updates: [text_chunk("the "), text_chunk("answer")],
          stop_reason: "end_turn"
        )

      {:ok, transcript} = drive(agent, "what is it?")

      assert Transcript.text(transcript) == "the answer"
      assert transcript.session_id == "scripted-session"
      assert transcript.stop_reason == "end_turn"
    end

    test "a tool call and its result thread on one id" do
      {:ok, agent} =
        ScriptedAgent.start_link(
          updates: [
            %{
              "sessionUpdate" => "tool_call",
              "toolCallId" => "t1",
              "title" => "curl api.stripe.com",
              "status" => "pending"
            },
            %{
              "sessionUpdate" => "tool_call_update",
              "toolCallId" => "t1",
              "status" => "completed"
            }
          ],
          stop_reason: "end_turn"
        )

      {:ok, transcript} = drive(agent, "call stripe")

      assert [%{kind: :tool_use}] = Transcript.of_kind(transcript, :tool_use)
      assert [%{kind: :tool_result}] = Transcript.of_kind(transcript, :tool_result)
    end

    test "a permission request is denied, because nobody is there to answer it" do
      # M0 runs one prompt unattended. Denying is the honest answer: the
      # agent is told no and the record shows it, rather than the turn
      # hanging on a question nothing will answer.
      {:ok, agent} =
        ScriptedAgent.start_link(
          permission: %{
            "toolCall" => %{"toolCallId" => "t1", "title" => "rm -rf /"},
            "options" => [%{"optionId" => "yes", "name" => "Allow", "kind" => "allow_once"}]
          },
          updates: [text_chunk("fine")],
          stop_reason: "end_turn"
        )

      {:ok, transcript} = drive(agent, "delete everything")

      # The agent offered only an "allow" option, so there is no rejection
      # to select and the protocol's own "nothing was selected" is the
      # answer. `Managoat.ACP.Permissions.deny_outcome/1` picks it.
      assert_received {:scripted_agent, :permission_answered, %{"outcome" => "cancelled"}}
      assert transcript.stop_reason == "end_turn"
    end

    test "a turn that outlasts its deadline returns what it had" do
      # An agent that never answers: the writer accepts frames and nothing
      # ever comes back, which is what a wedged adapter looks like.
      {:ok, peer} =
        Peer.start(
          owner: self(),
          writer: fn _iodata -> :ok end,
          ref: make_ref(),
          prompt: "wait forever",
          mode: :run,
          session_id: nil
        )

      ctx = %{command_ref: make_ref(), peer: peer, transcript: Transcript.new()}
      deadline = System.monotonic_time(:millisecond) + 150

      assert {:error, {:turn_timeout, %Transcript{}}} = Run.drive(ctx, deadline)
      Peer.close(peer)
    end

    test "an adapter that exits before the turn ends is an error, not an empty transcript" do
      ref = make_ref()
      send(self(), {:exit, %{ref: ref}, 127})

      ctx = %{command_ref: ref, peer: nil, transcript: Transcript.new()}

      assert {:error, {:adapter_exited, 127, ""}} =
               Run.drive(ctx, System.monotonic_time(:millisecond) + 1_000)
    end
  end

  # ── helpers ────────────────────────────────────────────────────────────────

  defp run(policy, opts) do
    parent = Keyword.get(opts, :stages)

    on_stage =
      if parent do
        # The box is destroyed at the end of the run, taking the Fake's
        # record of its policy with it, so a test that wants to see the seal
        # has to look while the turn is running.
        fn stage, status ->
          capture_policies(parent, stage, status)
          send(parent, {:stage, stage, status})
        end
      else
        fn _stage, _status -> :ok end
      end

    Run.start(
      policy: policy,
      prompt: "say hello",
      provider: :fake_box,
      runtime: "claude",
      vars: @vars,
      broker_host: Keyword.get(opts, :broker_host, "broker.example:14322"),
      broker_name: unique_name(),
      timeout: 2_000,
      on_stage: on_stage
    )
  end

  # The stages actually reported, in order. Only the named ones — "broker"
  # carries a payload rather than a lifecycle and is not part of the
  # ordering under test.
  defp stages(acc \\ []) do
    receive do
      {:stage, "broker", _status} -> stages(acc)
      {:stage, stage, :started} -> stages([stage | acc])
      {:stage, _stage, _status} -> stages(acc)
    after
      0 -> Enum.reverse(acc)
    end
  end

  defp drive(agent, prompt) do
    {:ok, peer} =
      Peer.start(
        owner: self(),
        writer: ScriptedAgent.writer(agent),
        ref: make_ref(),
        prompt: prompt,
        mode: :run,
        session_id: nil,
        # Not the library's default. `Managoat.ACP.Permissions.verdict_for/2`
        # falls back to `auto_allow`, so a peer started without this
        # approves every tool call itself and the owner is never asked.
        permission_policy: Run.default_permission_policy()
      )

    :ok = ScriptedAgent.connect(agent, peer)

    ctx = %{command_ref: make_ref(), peer: peer, transcript: Transcript.new()}
    result = Run.drive(ctx, System.monotonic_time(:millisecond) + 5_000)
    Peer.close(peer)
    result
  end

  defp capture_policies(parent, "turn", :started),
    do: send(parent, {:policies, applied_policies()})

  defp capture_policies(_parent, _stage, _status), do: :ok

  # Every network policy the fake box had applied to it this test.
  defp applied_policies do
    {:ok, names} = Sandbox.list_all_names(:fake_box)
    names |> Enum.map(&Fake.policy/1) |> Enum.reject(&is_nil/1)
  end

  defp text_chunk(text) do
    %{"sessionUpdate" => "agent_message_chunk", "content" => %{"type" => "text", "text" => text}}
  end

  defp unique_name, do: Module.concat(__MODULE__, "B#{System.unique_integer([:positive])}")
end
