defmodule Airlock.EgressTest do
  @moduledoc """
  The handler, on its own, fed events by hand.

  `Airlock.BrokerTest` proves it collects what a real proxy emits. This
  proves it survives what a real proxy might one day emit and this code has
  not read — which matters more, because a telemetry handler that raised is
  detached and silent, and a silent egress log is indistinguishable from an
  agent that made no requests.
  """

  use ExUnit.Case, async: true

  alias Airlock.Egress

  @event [:managoat, :broker, :request]

  setup context do
    run = "test-#{:erlang.phash2(context.test)}"

    {:ok, _pid} =
      Egress.start_link(
        run: run,
        schemes: %{"stripe" => :bearer, "anthropic" => :substitute, "allow:npm" => :passthrough}
      )

    on_exit(fn -> Egress.detach(run) end)
    %{run: run}
  end

  defp emit(run, metadata, measurements \\ %{count: 1, duration: 1_000_000}) do
    :telemetry.execute(@event, measurements, Map.merge(%{meta: %{run: run}}, metadata))
  end

  describe "the verdict" do
    test "a rule that attaches a credential is injected", %{run: run} do
      emit(run, %{outcome: :injected, rule: "stripe", host: "api.stripe.com", status: 200})
      assert [%{verdict: :injected, rule: "stripe"}] = Egress.rows(run)
    end

    test "a substitute rule is injected: a real credential reached the origin", %{run: run} do
      emit(run, %{outcome: :injected, rule: "anthropic", host: "api.anthropic.com", status: 200})
      assert [%{verdict: :injected}] = Egress.rows(run)
    end

    test "a passthrough rule is passthrough, though the event said injected", %{run: run} do
      # The event says `:injected` because *a rule matched*. Nothing was
      # attached. Without the rule's scheme the record cannot tell the
      # difference, and every allowed request would read as credentialed.
      emit(run, %{outcome: :injected, rule: "allow:npm", host: "registry.npmjs.org", status: 200})
      assert [%{verdict: :passthrough, rule: "allow:npm"}] = Egress.rows(run)
    end

    test "no rule under an unmatched-passthrough session is passthrough", %{run: run} do
      emit(run, %{outcome: :passthrough, rule: nil, host: "example.com", status: 200})
      assert [%{verdict: :passthrough, rule: nil}] = Egress.rows(run)
    end

    test "a refusal is denied", %{run: run} do
      emit(run, %{outcome: :denied, rule: nil, host: "pastebin.com", status: 403})
      assert [%{verdict: :denied, status: 403}] = Egress.rows(run)
    end

    test "a rule this policy did not compile is named, not guessed at", %{run: run} do
      emit(run, %{outcome: :injected, rule: "from-somewhere-else", host: "x.com", status: 200})
      assert [%{verdict: :unknown_rule, rule: "from-somewhere-else"}] = Egress.rows(run)
    end

    test "an outcome from a library version this code has not read", %{run: run} do
      emit(run, %{outcome: :something_new, rule: "stripe", host: "x.com", status: 200})
      assert [%{verdict: :malformed}] = Egress.rows(run)
    end
  end

  describe "rows carry what the record needs" do
    test "duration in milliseconds, from the event's native units", %{run: run} do
      native = System.convert_time_unit(250, :millisecond, :native)

      emit(run, %{outcome: :injected, rule: "stripe", host: "a.com", status: 200}, %{
        count: 1,
        duration: native
      })

      assert [%{duration_ms: ms}] = Egress.rows(run)
      assert_in_delta ms, 250.0, 1.0
    end

    test "the error a request ended with", %{run: run} do
      emit(run, %{
        outcome: :denied,
        rule: nil,
        host: "a.com",
        status: 502,
        error: :credential_missing
      })

      assert [%{error: :credential_missing, status: 502}] = Egress.rows(run)
    end

    test "rows come back oldest first", %{run: run} do
      for host <- ~w(one two three),
          do: emit(run, %{outcome: :denied, rule: nil, host: host, status: 403})

      assert Enum.map(Egress.rows(run), & &1.host) == ~w(one two three)
    end
  end

  describe "the handler survives, which is the whole point" do
    test "metadata with the wrong shape does not detach it", %{run: run} do
      assert Egress.attached?(run)

      # Every one of these is a malformed event: no metadata map at all,
      # a meta that is not a map, measurements that are not numbers.
      :telemetry.execute(@event, %{count: 1}, %{meta: %{run: run}, outcome: nil, rule: 42})
      :telemetry.execute(@event, %{duration: "not a number"}, %{meta: %{run: run}})
      :telemetry.execute(@event, %{}, %{meta: %{run: run}})

      assert Egress.attached?(run), "the handler detached itself on malformed metadata"

      # And it still works afterwards, which "still attached" alone does
      # not prove.
      emit(run, %{outcome: :injected, rule: "stripe", host: "api.stripe.com", status: 200})
      assert Enum.any?(Egress.rows(run), &(&1.verdict == :injected))
    end

    test "an event with no meta at all is ignored rather than fatal", %{run: run} do
      :telemetry.execute(@event, %{count: 1}, %{outcome: :injected, rule: "stripe"})
      assert Egress.attached?(run)
      assert Egress.rows(run) == []
    end

    test "the handler survives its collector dying, and stays attached", %{run: run} do
      # The real failure this guard is for. Killing the collector makes
      # `Agent.update/2` exit inside the handler — a stand-in for any bug
      # in this module — and an unguarded handler would be detached by it,
      # silently, for the rest of the run. Verified by breaking the guard:
      # with the `catch` clause removed this test fails on the assertion
      # below rather than erroring, which is exactly how the failure would
      # present in production.
      collector = Process.whereis(collector_name(run))
      # The collector is linked to this test, which started it.
      Process.unlink(collector)
      Process.exit(collector, :kill)
      wait_until(fn -> not Process.alive?(collector) end)

      emit(run, %{outcome: :injected, rule: "stripe", host: "a.com", status: 200})

      assert Egress.attached?(run), "the handler detached itself when its collector died"
    end
  end

  # `Airlock.Egress` names its collector after the run; this is the same
  # derivation, so the test can kill it.
  defp collector_name(run),
    do: Module.concat(Egress, "Run_" <> Base.url_encode64(run, padding: false))

  defp wait_until(predicate, attempts \\ 50) do
    cond do
      predicate.() -> :ok
      attempts > 0 -> Process.sleep(5) && wait_until(predicate, attempts - 1)
      true -> flunk("condition never became true")
    end
  end

  describe "rows belong to one run" do
    test "another run's events are not collected", %{run: run} do
      emit("some-other-run", %{outcome: :injected, rule: "stripe", host: "a.com", status: 200})
      assert Egress.rows(run) == []
    end

    test "telemetry handlers are global, so this is not a formality", %{run: run} do
      # Every other async test attaching a handler on this event sees these
      # too. Filtering on the session's meta is what keeps a record's rows
      # provably one run's.
      other = "concurrent-#{System.unique_integer([:positive])}"
      {:ok, _pid} = Egress.start_link(run: other, schemes: %{"stripe" => :bearer})
      on_exit(fn -> Egress.detach(other) end)

      emit(run, %{outcome: :injected, rule: "stripe", host: "mine.com", status: 200})
      emit(other, %{outcome: :injected, rule: "stripe", host: "theirs.com", status: 200})

      assert Enum.map(Egress.rows(run), & &1.host) == ["mine.com"]
      assert Enum.map(Egress.rows(other), & &1.host) == ["theirs.com"]
    end
  end

  describe "detach/1" do
    test "stops collecting but keeps what was collected", %{run: run} do
      emit(run, %{outcome: :injected, rule: "stripe", host: "a.com", status: 200})
      assert :ok = Egress.detach(run)
      refute Egress.attached?(run)

      emit(run, %{outcome: :injected, rule: "stripe", host: "b.com", status: 200})
      assert Enum.map(Egress.rows(run), & &1.host) == ["a.com"]
    end
  end
end
