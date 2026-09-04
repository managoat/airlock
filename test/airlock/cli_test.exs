defmodule Airlock.CLITest do
  @moduledoc """
  Flag parsing, which is where `run`'s branches are.

  Driven through `Airlock.CLI.parse_flags/1` rather than `main/1`: every
  error path in the command halts the VM, so a test that drove `main/1`
  would take ExUnit with it.
  """

  use ExUnit.Case, async: true

  alias Airlock.CLI
  alias Airlock.Render

  describe "defaults" do
    test "are the ones a first run should get" do
      assert {:ok, opts} = CLI.parse_flags([])

      assert opts[:runtime] == "claude"
      assert opts[:provider] == :sprites
      assert opts[:unsealed] == false
      assert opts[:broker_port] == 0
      assert opts[:broker_host] == nil
    end

    test "permissions default to ask, not the library's auto_allow" do
      # `Managoat.ACP.Permissions.verdict_for/2` falls back to auto_allow, so
      # a peer started the obvious way approves every tool call itself. For
      # an unattended turn on a box holding a live proxy address that is the
      # wrong way round, and this is where the inversion is pinned.
      assert {:ok, opts} = CLI.parse_flags([])
      assert opts[:permission_policy] == %{"default" => "ask"}
    end
  end

  describe "flags" do
    test "a tunnel needs a known port and the address the box reaches it by" do
      assert {:ok, opts} =
               CLI.parse_flags([
                 "--broker-port",
                 "14322",
                 "--broker-host",
                 "4.tcp.ngrok.io:12171"
               ])

      assert opts[:broker_port] == 14_322
      assert opts[:broker_host] == "4.tcp.ngrok.io:12171"
    end

    test "timeout is given in seconds and passed in milliseconds" do
      assert {:ok, opts} = CLI.parse_flags(["--timeout", "300"])
      assert opts[:timeout] == 300_000
    end

    test "permissions and provider are taken as given" do
      assert {:ok, opts} = CLI.parse_flags(["--permissions", "auto_allow", "--provider", "e2b"])
      assert opts[:permission_policy] == %{"default" => "auto_allow"}
      assert opts[:provider] == :e2b
    end

    test "--unsealed is the only way past a box that cannot be sealed" do
      assert {:ok, opts} = CLI.parse_flags(["--unsealed"])
      assert opts[:unsealed] == true
    end
  end

  describe "refusals name the mistake" do
    test "a provider that does not exist" do
      assert {:error, {:bad_provider, "fly", allowed}} = CLI.parse_flags(["--provider", "fly"])
      assert "sprites" in allowed

      assert Render.run_error({:bad_provider, "fly", allowed}, "p.yaml") =~ "no such provider"
    end

    test "a permission verdict that does not exist" do
      assert {:error, {:bad_permissions, "yolo", allowed}} =
               CLI.parse_flags(["--permissions", "yolo"])

      assert "auto_deny" in allowed
    end

    test "an option nobody defined" do
      assert {:error, {:bad_flags, ["--danger"]}} = CLI.parse_flags(["--danger"])
    end

    test "a stray argument, which is usually an unquoted prompt" do
      assert {:error, {:unexpected_args, ["and", "then"]}} = CLI.parse_flags(["and", "then"])
    end
  end
end
