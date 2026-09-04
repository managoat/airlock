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
      :ok
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
