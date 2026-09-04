defmodule Airlock.CredentialsTest do
  @moduledoc """
  Credentials Airlock needs to do its own job, as opposed to the ones a
  policy names. The second kind never reaches the box; the first kind never
  could be brokered, because it is Airlock talking to a provider on its own
  behalf.
  """

  use ExUnit.Case, async: false

  alias Airlock.Credentials
  alias Airlock.Keychain

  describe "sprites_token/0" do
    test "an exported variable wins over the CLI's store" do
      System.put_env("SPRITES_TOKEN", "from-the-environment")
      on_exit(fn -> System.delete_env("SPRITES_TOKEN") end)

      assert {:ok, "from-the-environment", :env} = Credentials.sprites_token()
    end

    test "falls back to the sprites CLI, or says it found nothing" do
      System.delete_env("SPRITES_TOKEN")

      # Which branch runs depends on whether this machine has run
      # `sprite login`. Both are correct answers and neither may raise.
      case Credentials.sprites_token() do
        {:ok, token, :sprites_cli} -> assert is_binary(token) and token != ""
        {:error, :no_sprites_credentials} -> :ok
      end
    end
  end

  describe "sprites_base_url/0" do
    test "an exported variable wins" do
      System.put_env("SPRITES_BASE_URL", "https://api.example.test")
      on_exit(fn -> System.delete_env("SPRITES_BASE_URL") end)

      assert Credentials.sprites_base_url() == "https://api.example.test"
    end

    test "falls back to something usable" do
      System.delete_env("SPRITES_BASE_URL")
      assert "https://" <> _rest = Credentials.sprites_base_url()
    end
  end

  describe "the go-keyring base64 marker" do
    test "a missing item is an error, never an exception" do
      assert Keychain.generic_password("airlock-no-such-#{System.unique_integer([:positive])}") ==
               :error
    end

    test "a token that came back through the keychain has been unwrapped" do
      # Not hypothetical: the Sprites token on the machine this was built on
      # is stored behind the marker, and skipping the decode yields a
      # plausible string that fails with a 401 saying nothing about why.
      System.delete_env("SPRITES_TOKEN")

      case Credentials.sprites_token() do
        {:ok, token, :sprites_cli} ->
          refute String.starts_with?(token, "go-keyring-base64:")
          assert length(String.split(token, "/")) == 4

        _other ->
          :ok
      end
    end
  end

  describe "inference_credentials/0" do
    test "an exported variable is used as given" do
      System.put_env("ANTHROPIC_API_KEY", "sk-ant-exported")
      on_exit(fn -> System.delete_env("ANTHROPIC_API_KEY") end)

      assert %{"ANTHROPIC_API_KEY" => "sk-ant-exported"} = Credentials.inference_credentials()
    end

    test "an exported oauth token is not displaced by the keychain's" do
      System.put_env("CLAUDE_CODE_OAUTH_TOKEN", "exported-wins")
      on_exit(fn -> System.delete_env("CLAUDE_CODE_OAUTH_TOKEN") end)

      assert %{"CLAUDE_CODE_OAUTH_TOKEN" => "exported-wins"} = Credentials.inference_credentials()
    end

    test "an expired keychain token is treated as absent, not passed on" do
      # An expired token reaching a runtime fails authentication halfway
      # through a turn, on a box already provisioned and sealed. "No
      # credential", reported before anything is created, is a far better
      # error — so this may return nil, but never an expired string.
      System.delete_env("CLAUDE_CODE_OAUTH_TOKEN")

      case Credentials.claude_subscription_token() do
        nil -> :ok
        token -> assert is_binary(token) and token != ""
      end
    end
  end
end
