defmodule Airlock.MixProject do
  use Mix.Project

  @version "0.1.0"

  def project do
    [
      app: :airlock,
      version: @version,
      elixir: "~> 1.18",
      start_permanent: Mix.env() == :prod,
      elixirc_paths: elixirc_paths(Mix.env()),
      elixirc_options: [warnings_as_errors: true],
      escript: escript(),
      deps: deps(),
      aliases: aliases(),
      dialyzer: [plt_add_apps: [:mix, :ex_unit], ignore_warnings: ".dialyzer_ignore.exs"]
    ]
  end

  # An escript does not start applications and never runs config/runtime.exs;
  # `Airlock.CLI.main/1` does both jobs explicitly. This stanza is what the
  # library code sees under `mix test` and `iex -S mix`, where applications
  # *are* started.
  def application do
    [extra_applications: [:logger]]
  end

  # `mix precommit` runs the test suite, and an alias does not switch
  # MIX_ENV on its own — without this it would run `mix test` in :dev and
  # refuse. Everything the alias runs is available in :test.
  def cli, do: [preferred_envs: [precommit: :test]]

  # `test/support` holds a test origin and a proxy client: things the tests
  # drive the broker with, not things Airlock ships.
  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_env), do: ["lib"]

  defp escript do
    [main_module: Airlock.CLI, name: "airlock"]
  end

  defp deps do
    [
      # The machine layer, and `NetworkPolicy` — the sandbox's own
      # default-deny egress. 0.2.1.
      {:managoat_sandbox, "~> 0.2.1"},
      # The user's own machine as a sandbox provider, so the broker is
      # trivially reachable from the box. 0.2.1.
      {:managoat_runner, "~> 0.2.1"},
      # The egress credential proxy and the per-request telemetry event.
      # Four minors past what CLAUDE.md records; see NOTES-M0.md.
      {:managoat_broker, "~> 0.8.0"},
      # The policy file.
      {:yaml_elixir, "~> 2.9"},
      # The transport for a local box. `managoat_runner` ships the `WebSock`
      # behaviour only and says the adapter that mounts a handler on a Plug
      # connection belongs to the host application; these are that.
      {:bandit, "~> 1.5"},
      {:websock_adapter, "~> 0.5"},
      {:plug, "~> 1.16"},
      # A WebSocket client, to drive the endpoint in a test with something
      # that is not the library's own in-BEAM stand-in.
      {:mint_web_socket, "~> 1.0", only: :test},
      {:ex_doc, "~> 0.34", only: :dev, runtime: false},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      # dialyxir is pinned to the commit that added OTP 28 support; 1.4.7
      # crashes on OTP 28 warnings. Same pin every managoat library uses.
      {:dialyxir,
       github: "jeremyjh/dialyxir",
       ref: "3553678f4d69281ac6db61034bcf35bcb30cfd78",
       only: [:dev, :test],
       runtime: false}
    ]
  end

  defp aliases do
    [
      precommit: [
        "format --check-formatted",
        "compile --warnings-as-errors",
        "credo --strict",
        "test",
        "dialyzer"
      ]
    ]
  end
end
