defmodule Airlock.BoxTest do
  @moduledoc """
  The trust store, and the two ways of getting it wrong.

  Both were made for real on the way to M0's first working run
  (`NOTES-M0.md` §9), and both fail the same way: silently at provision
  time, then as a TLS error against a host nobody suspects.
  """

  use ExUnit.Case, async: true

  alias Airlock.Box

  describe "ca_env/0" do
    test "NODE_EXTRA_CA_CERTS takes the broker root alone, because it is additive" do
      # Node ignores the OS store entirely, and every ACP adapter but
      # gemini's is a Node program — so this is the variable that decides
      # whether the agent can talk to its own API at all.
      assert Box.ca_env()["NODE_EXTRA_CA_CERTS"] == Box.ca_path()
    end

    test "every replacing variable takes the system bundle, never the root alone" do
      # The mistake: pointing these at the broker root. They *replace* the
      # bundle rather than adding to it, so a tool told to trust one
      # certificate rejects every host the broker is not in front of —
      # `pip install` and `cargo fetch` fail with UnknownIssuer.
      env = Box.ca_env()

      for name <-
            ~w(SSL_CERT_FILE REQUESTS_CA_BUNDLE CARGO_HTTP_CAINFO GIT_SSL_CAINFO CURL_CA_BUNDLE) do
        assert env[name] == Box.system_ca_bundle(),
               "#{name} must name the system bundle, not the broker root alone"

        refute env[name] == Box.ca_path()
      end
    end

    test "uv is turned off its bundled roots and onto the OS store" do
      assert Box.ca_env()["UV_NATIVE_TLS"] == "1"
    end

    test "the two paths are different, which is the whole point" do
      refute Box.ca_path() == Box.system_ca_bundle()
    end
  end

  describe "name_for/2" do
    test "an explicit name is taken as given" do
      assert {:ok, "chosen"} = Box.name_for(:sprites, "chosen")
    end

    test "a cloud box gets a fresh airlock-prefixed name" do
      assert {:ok, "airlock-" <> rest} = Box.name_for(:sprites, nil)
      assert String.length(rest) == 16
    end

    test "two boxes never collide" do
      assert {:ok, one} = Box.name_for(:sprites, nil)
      assert {:ok, two} = Box.name_for(:sprites, nil)
      refute one == two
    end

    test "a runner with nothing connected says so, rather than minting a name that cannot work" do
      # The runner refuses any name that is not `runner-<32 hex>-<8 hex>`,
      # because a name is the only thing Managoat.Sandbox hands an adapter.
      # Minting an ordinary one fails at create with
      # `:not_a_runner_sandbox_name`, which points nowhere near the cause.
      assert {:error, :no_runner_connected} = Box.name_for(:runner, nil)
    end
  end
end
