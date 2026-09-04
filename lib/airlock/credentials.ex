defmodule Airlock.Credentials do
  @moduledoc """
  Where a credential comes from when the policy did not say.

  Two different jobs, and only one of them is this module's:

    * the credentials a **policy** names (`from: env:STRIPE_KEY`) are
      resolved by `Airlock.Policy.Compile.rules/2` against a variable map,
      and they are the ones that never reach the box;
    * the credentials **Airlock itself** needs to do its job — a Sprites
      token to create a box at all — are resolved here. They are not
      brokered and never could be: the whole point of a broker is that it
      sits between the box and an origin, and this is Airlock talking to a
      provider on its own behalf.

  ## Found, not configured

  `Managoat.Sandbox.Config` reads each adapter's settings from
  `:managoat_sandbox`'s application environment, which is what
  `config/runtime.exs` would fill in — and an escript never runs it. So
  something has to lift these across at boot, and while it is doing that it
  may as well look where the credential already is:

  | | |
  |---|---|
  | 1 | `SPRITES_TOKEN` in the environment |
  | 2 | the Sprites CLI's own store: `~/.sprites/sprites.json` for the current selection's `keyring_key`, then the login keychain |

  Order matters that way round so an explicit variable always wins — a
  second org, a scratch token, CI.

  ## The base64 marker

  The keychain item is written by Go's `99designs/keyring`, which stores
  anything that is not plain ASCII as base64 behind a
  `go-keyring-base64:` marker. `Airlock.Keychain` unwraps it. Skipping that
  produces a token that looks plausible and fails with a `401` saying
  nothing about why — which is how it earned its comment in goatherd and
  its test here.
  """

  alias Airlock.Keychain
  alias Managoat.Sandbox

  # The Sprites CLI's keychain service, and the file it records which
  # keyring item belongs to the selected org.
  @sprites_service "sprites-cli:manual-tokens"
  @sprites_config ".sprites/sprites.json"
  @claude_service "Claude Code-credentials"

  @typedoc "Where a credential was found, for a line of output that is not the credential."
  @type source :: :env | :sprites_cli | :none

  @doc """
  The Sprites API token, with where it came from.

  `{:ok, token, source}`, or `{:error, reason}` with something a human can
  act on. Never returns the token in an error.
  """
  @spec sprites_token() :: {:ok, String.t(), source()} | {:error, term()}
  def sprites_token do
    case System.get_env("SPRITES_TOKEN") do
      token when is_binary(token) and token != "" ->
        {:ok, token, :env}

      _ ->
        from_sprites_cli()
    end
  end

  @doc """
  The Sprites API base URL: the environment, then the CLI's current
  selection, then the public API.
  """
  @spec sprites_base_url() :: String.t()
  def sprites_base_url do
    with nil <- System.get_env("SPRITES_BASE_URL"),
         {:ok, %{"current_selection" => %{"url" => url}}} <- sprites_config() do
      url
    else
      url when is_binary(url) -> url
      _ -> "https://api.sprites.dev"
    end
  end

  @doc """
  The org the Sprites CLI currently has selected, or `nil`.

  Only for saying which account a box is about to be created in. Nothing
  depends on it.
  """
  @spec sprites_org() :: String.t() | nil
  def sprites_org do
    case sprites_config() do
      {:ok, %{"current_selection" => %{"org" => org}}} -> org
      _ -> nil
    end
  end

  @doc """
  An inference credential for the agent, if this machine has one.

  Returns the variable name and the value, so a policy that names
  `from: env:ANTHROPIC_API_KEY` can be satisfied without the caller
  exporting anything. Checked in the order
  `Managoat.Runtimes.Claude.default_env/2` prefers them, which is the
  subscription token first: it bills against a Claude.ai plan rather than
  metered API usage.

  Falls back to **Claude Code's own login keychain item**, whose
  `claudeAiOauth.accessToken` is a `CLAUDE_CODE_OAUTH_TOKEN`. It bills the
  subscription this machine is already signed in to rather than metered API
  usage, which is the point: Airlock adds no metering of its own because it
  never holds a credential of its own.
  """
  @spec inference_credentials() :: %{optional(String.t()) => String.t()}
  def inference_credentials do
    from_env =
      for name <- ~w(CLAUDE_CODE_OAUTH_TOKEN ANTHROPIC_API_KEY OPENAI_API_KEY GEMINI_API_KEY),
          value = System.get_env(name),
          is_binary(value) and value != "",
          into: %{},
          do: {name, value}

    case claude_subscription_token() do
      nil -> from_env
      token -> Map.put_new(from_env, "CLAUDE_CODE_OAUTH_TOKEN", token)
    end
  end

  @doc """
  Claude Code's subscription access token from the login keychain, or `nil`.

  Nil when the item is missing, unparseable, or **expired**. An expired
  token reaching a runtime produces an authentication failure halfway
  through a turn, on a box that has already been provisioned and sealed —
  a far worse error than "no credential" reported before anything is
  created.

  Not refreshed here. Refreshing is Claude Code's job and doing it from
  another process would race the tool that owns the item.
  """
  @spec claude_subscription_token() :: String.t() | nil
  def claude_subscription_token do
    with {:ok, body} <- Keychain.generic_password(@claude_service),
         {:ok, %{"claudeAiOauth" => oauth}} <- Jason.decode(body),
         token when is_binary(token) <- oauth["accessToken"],
         false <- expired?(oauth["expiresAt"]) do
      token
    else
      _ -> nil
    end
  end

  # `expiresAt` is milliseconds since the epoch. Anything else is treated as
  # expired: a token whose expiry cannot be read is not one to bet a
  # provisioned box on.
  defp expired?(expires_at) when is_integer(expires_at),
    do: expires_at <= System.system_time(:millisecond)

  defp expired?(_expires_at), do: true

  # ── the sprites CLI's store ────────────────────────────────────────────────

  defp from_sprites_cli do
    with {:ok, config} <- sprites_config(),
         {:ok, key} <- keyring_key(config),
         {:ok, token} <- Keychain.generic_password(@sprites_service, key) do
      {:ok, token, :sprites_cli}
    else
      _ -> {:error, :no_sprites_credentials}
    end
  end

  defp sprites_config do
    path = Path.join(System.user_home!(), @sprites_config)

    with {:ok, body} <- File.read(path),
         {:ok, json} <- Jason.decode(body) do
      {:ok, json}
    else
      _ -> :error
    end
  end

  # The keyring item for the org the CLI has selected. A config naming an
  # org it has no key for is the same as no credential: `sprite login`
  # again is the fix either way.
  defp keyring_key(%{"current_selection" => %{"url" => url, "org" => org}, "urls" => urls}) do
    case get_in(urls, [url, "orgs", org, "keyring_key"]) do
      key when is_binary(key) -> {:ok, key}
      _ -> :error
    end
  end

  defp keyring_key(_config), do: :error

  @doc """
  Is `provider` configured well enough to be talked to at all?

  Every `managoat_sandbox` adapter reads its own application environment
  and **raises** on a missing key, from inside the library and several
  frames down — `Managoat.Sandbox.Sprites.Client.get!/0` and friends. In a
  mix project `config/runtime.exs` fills that in; an escript never runs
  it, which is `NOTES-M0.md` §8's purest example of the trap, and
  `Airlock.Boot` is what lifts the variables across.

  So every command that is about to touch a provider asks this first, and
  gets back an error naming the variable rather than a stack trace.

  The runner is not checked: it authenticates a daemon at
  `Airlock.Box.Endpoint`, not a provider API, and the fakes authenticate
  nothing.
  """
  @spec provider_ready(atom()) :: :ok | {:error, {:provider_not_configured, atom(), String.t()}}
  def provider_ready(provider) do
    case provider_credential(provider) do
      :none -> :ok
      {_key, value} when is_binary(value) and value != "" -> :ok
      {key, _} -> {:error, {:provider_not_configured, provider, key}}
    end
  end

  defp provider_credential(:sprites),
    do: {"SPRITES_TOKEN", Sandbox.Config.get(Managoat.Sandbox.Sprites, :token)}

  defp provider_credential(:e2b),
    do: {"E2B_API_KEY", Sandbox.Config.get(Managoat.Sandbox.E2B, :api_key)}

  defp provider_credential(:daytona),
    do: {"DAYTONA_API_KEY", Sandbox.Config.get(Managoat.Sandbox.Daytona, :api_key)}

  defp provider_credential(_provider), do: :none
end
