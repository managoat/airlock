defmodule Airlock.Boot do
  @moduledoc """
  What an escript has to do for itself.

  `CLAUDE.md`: "An escript does not start applications and never runs
  `config/runtime.exs`. Whatever entry point you write does both jobs
  explicitly." This is both jobs, in one place that `Airlock.CLI` and the
  tests both call, so the shipped artefact and the test suite boot the same
  way.

  Under `mix test` and `iex -S mix` the applications are already up and
  `ensure_all_started/1` is a no-op, which is the point: there is no second
  code path that only runs in production.
  """

  alias Airlock.Box.Host

  @applications [:logger, :crypto, :ssl, :telemetry, :yaml_elixir, :bandit]

  # Provider credentials, and the exact shape of the escript trap: each
  # library reads its own application environment, `config/runtime.exs`
  # is where a mix project would put these, and an escript never runs it.
  # Without this, `SPRITES_TOKEN` in the environment does **nothing** and
  # the run dies inside the library with "SPRITES_TOKEN is not set" while
  # the variable is plainly set — the most confusing shape of wrong
  # available here.
  @provider_credentials [
    {Managoat.Sandbox.Sprites, :token, "SPRITES_TOKEN"},
    {Managoat.Sandbox.Sprites, :base_url, "SPRITES_BASE_URL"},
    {Managoat.Sandbox.E2B, :api_key, "E2B_API_KEY"},
    {Managoat.Sandbox.Daytona, :api_key, "DAYTONA_API_KEY"}
  ]

  @doc """
  Start the applications an escript does not, and set the configuration
  `config/runtime.exs` would have.

  Returns `:ok`, or `{:error, {app, reason}}` naming the application that
  would not start.
  """
  @spec boot() :: :ok | {:error, term()}
  def boot do
    with :ok <- start_applications() do
      Host.configure()
      configure_providers()
      start_host()
      :ok
    end
  end

  @doc """
  Lift provider credentials out of the environment into the libraries'
  application environment. See `@provider_credentials`.

  A variable that is not set is skipped rather than written as `nil`,
  because `Managoat.Sandbox.Config` treats a `nil` as unset anyway and
  writing one would only obscure a value set some other way.
  """
  @spec configure_providers() :: :ok
  def configure_providers do
    for {scope, key, var} <- @provider_credentials,
        value = System.get_env(var),
        is_binary(value) and value != "" do
      settings = Application.get_env(:managoat_sandbox, scope, [])
      Application.put_env(:managoat_sandbox, scope, Keyword.put(settings, key, value))
    end

    :ok
  end

  # The registry a local box registers in. Started here rather than left to
  # a supervision tree the escript does not have; harmless when nothing
  # ever connects, and `Airlock.Box.Host.online/0` would raise without it.
  defp start_host do
    case Host.start_link([]) do
      {:ok, _pid} -> :ok
      {:error, {:already_started, _pid}} -> :ok
      {:error, _reason} -> :ok
    end
  end

  defp start_applications do
    Enum.reduce_while(@applications, :ok, fn app, :ok ->
      case Application.ensure_all_started(app) do
        {:ok, _started} -> {:cont, :ok}
        {:error, reason} -> {:halt, {:error, {app, reason}}}
      end
    end)
  end
end
