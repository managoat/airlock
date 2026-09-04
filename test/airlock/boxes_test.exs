defmodule Airlock.BoxesTest do
  @moduledoc """
  Finding and destroying the boxes a killed run left behind.

  The only interesting question here is what counts as Airlock's, because
  `reap/2` destroys what it matches and the account it is pointed at is
  the user's whole account.
  """

  use ExUnit.Case, async: false

  alias Airlock.Boxes
  alias Airlock.CLI
  alias Airlock.Render
  alias Airlock.Test.FakeBox
  alias Managoat.Sandbox
  alias Managoat.Sandbox.Fake

  setup do
    Fake.reset()
    adapters = Sandbox.adapters()
    Application.put_env(:managoat_sandbox, :adapters, Map.put(adapters, :fake_box, FakeBox))
    on_exit(fn -> Application.put_env(:managoat_sandbox, :adapters, adapters) end)
    :ok
  end

  describe "ours?/1" do
    test "matches exactly what Airlock.Box.name_for/2 mints" do
      assert Boxes.ours?("airlock-0123456789abcdef")
      refute Boxes.ours?("airlock-0123456789ABCDEF")
      refute Boxes.ours?("airlock-0123456789abcde")
      refute Boxes.ours?("airlock-0123456789abcdef0")
    end

    test "a prefix is not a match, deliberately" do
      # `reap/2` destroys what this matches. A prefix test would take
      # `airlock-staging` with it.
      refute Boxes.ours?("airlock-staging")
      refute Boxes.ours?("airlock")
      refute Boxes.ours?("my-airlock-0123456789abcdef")
    end

    test "a runner box is not matched, and structurally cannot be" do
      # A runner name carries the runner id, because that is the only thing
      # `Managoat.Sandbox` hands an adapter — there is no room for a prefix.
      refute Boxes.ours?("runner-#{String.duplicate("a", 32)}-#{String.duplicate("b", 8)}")
    end

    test "anything that is not a string is not ours" do
      refute Boxes.ours?(nil)
      refute Boxes.ours?(:airlock)
    end
  end

  describe "list/1" do
    test "reports Airlock's boxes and leaves everything else alone" do
      create("airlock-0123456789abcdef")
      create("airlock-fedcba9876543210")
      create("someone-elses-sandbox")
      create("airlock-staging")

      assert {:ok, boxes} = Boxes.list(:fake_box)

      assert Enum.map(boxes, & &1.name) == [
               "airlock-0123456789abcdef",
               "airlock-fedcba9876543210"
             ]

      assert Enum.all?(boxes, &(&1.status == :running))
    end

    test "an empty account is an empty list, not an error" do
      assert {:ok, []} = Boxes.list(:fake_box)
    end
  end

  describe "reap/2" do
    test "destroys what it is given and nothing else" do
      create("airlock-0123456789abcdef")
      create("someone-elses-sandbox")

      assert [{:ok, "airlock-0123456789abcdef"}] =
               Boxes.reap(:fake_box, ["airlock-0123456789abcdef"])

      assert {:ok, names} = Sandbox.list_all_names(:fake_box)
      assert MapSet.to_list(names) == ["someone-elses-sandbox"]
    end

    test "checks the name again rather than trusting the caller" do
      # This function destroys things, and the check costs nothing.
      create("someone-elses-sandbox")

      assert [{:refused, "someone-elses-sandbox"}] =
               Boxes.reap(:fake_box, ["someone-elses-sandbox"])

      assert {:ok, names} = Sandbox.list_all_names(:fake_box)
      assert MapSet.member?(names, "someone-elses-sandbox")
    end

    test "is safe to run twice: already gone is success" do
      create("airlock-0123456789abcdef")

      assert [{:ok, _}] = Boxes.reap(:fake_box, ["airlock-0123456789abcdef"])
      assert [{:ok, _}] = Boxes.reap(:fake_box, ["airlock-0123456789abcdef"])
    end
  end

  describe "the flags" do
    test "default to sprites and to not destroying anything" do
      assert {:ok, :sprites, false} = CLI.parse_box_flags([])
    end

    test "--yes is what a reap needs, and has to be said" do
      assert {:ok, :sprites, true} = CLI.parse_box_flags(["--yes"])
    end

    test "refuse a provider that is not one" do
      assert {:error, {:bad_provider, "aws", _}} = CLI.parse_box_flags(["--provider", "aws"])
    end

    test "refuse a stray argument rather than ignoring it" do
      assert {:error, {:unexpected_args, ["airlock-0123456789abcdef"]}} =
               CLI.parse_box_flags(["airlock-0123456789abcdef"])
    end
  end

  describe "what the terminal says" do
    test "a reap without --yes lists and refuses, rather than doing half of it" do
      text =
        Render.reap_refused([%{name: "airlock-0123456789abcdef", status: :running}], :sprites)

      assert text =~ "airlock-0123456789abcdef"
      assert text =~ "will not do it unasked"
      assert text =~ "--yes"
    end

    test "a truncated account stops the reap rather than reaping half of it" do
      # `Managoat.Sandbox.list_all_names/1` refuses with `:truncated`
      # rather than returning a partial set that looks whole, and a reap
      # against half an account is worse than one that did not run.
      assert Render.boxes_error(:truncated) =~ "partial one that looks"
    end

    test "each reaped box says what happened to it" do
      text =
        Render.reaped([
          {:ok, "airlock-0123456789abcdef"},
          {:refused, "someone-elses-sandbox"},
          {{:error, :timeout}, "airlock-fedcba9876543210"}
        ])

      assert text =~ "destroyed"
      assert text =~ "left alone"
      assert text =~ "failed: :timeout"
    end
  end

  defp create(name) do
    {:ok, _handle} = Sandbox.create(:fake_box, name)
  end
end
