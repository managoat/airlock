defmodule Airlock.Box.Host do
  @moduledoc """
  The `Managoat.Runner.Host` a local box is presented through.

  ## The guess was right, and it is already written

  `CLAUDE.md` lists this as what Airlock supplies to `managoat_runner`:
  "A `Runner.Host`. `Host.Local` over a plain `Registry` is the guess; it
  is M0's first task and the guess is unverified." `PLAN.md` puts it first
  for the same reason.

  Measured against 0.2.1: **`Managoat.Runner.Host.Local` ships in the
  library**, is exactly a `Registry` with `keys: :unique`, and is what the
  library's own tests run against — its moduledoc says "a consumer without
  a cluster" uses it as-is. So Airlock does not implement the behaviour.
  The six callbacks would be a transcription, and a transcription of a
  reference implementation is a second thing to keep in step with the
  library for no gain.

  What Airlock actually supplies is smaller and is here: the registry in a
  supervision tree, and the `config :managoat_runner, host:` key set at
  runtime rather than at compile time — because an escript never runs
  `config/runtime.exs` and `Managoat.Runner.Config.host!/1` raises on a
  missing key rather than defaulting.

  A host that needs presence broadcast or a row per runner implements the
  behaviour over its own registry; that is M3's problem, if it is anyone's.

  ## What is *not* here, and blocks a local box

  Two things, both found by reading 0.2.1 rather than by running it. They
  are why nothing above this module can bring up a local box yet, and they
  are recorded in `NOTES-M0.md`:

    * **the transport.** `managoat_runner` depends on `websock` — the
      behaviour only — and says the adapter that mounts a handler on a Plug
      connection "belongs to the host application". So the WebSocket
      endpoint a daemon dials *into* is Airlock's to write.
      `Airlock.Box.Endpoint` is it;
    * **the daemon.** `Managoat.Runner.FakeDaemon` is an in-BEAM stand-in
      whose sandboxes are maps of files and whose commands are scripted
      (`out:`, `exit:`); it runs nothing. Its moduledoc says "the Go daemon
      must agree with it", and that daemon is `fountain runner` in
      Fountain's private CLI (`cli/internal/runner`, ~4,300 lines of Go) —
      not one of the nine libraries and not on hex.

  So a local box is a real box only with a daemon Airlock does not have.
  Everything in this module and in `Airlock.Box.Endpoint` is verified
  against `FakeDaemon` and against a socket speaking the protocol by hand,
  which verifies the host and the transport and does not verify a box.
  """

  alias Managoat.Runner.Adapter
  alias Managoat.Runner.Config
  alias Managoat.Runner.Host.Local
  alias Managoat.Sandbox

  @doc """
  The child spec for the local host's registry.

  Put it in a supervision tree before anything that opens a connection:

      children = [Airlock.Box.Host]
  """
  @spec child_spec(term()) :: Supervisor.child_spec()
  def child_spec(opts), do: Local.child_spec(opts)

  @doc """
  Set the two application-environment keys a local box needs, and return
  the host module.

  Both are set here rather than in `config/config.exs` because an escript
  never runs `config/runtime.exs`, and a value that only exists under `mix`
  is a value that is missing from the shipped artefact. Both fail late and
  confusingly when unset, which is why they are set explicitly at boot
  rather than left to be discovered:

    * `config :managoat_runner, host:` — `Managoat.Runner.Config.host!/1`
      raises naming the key, but only at the first `call/3`, minutes into a
      run;
    * `config :managoat_sandbox, adapters:` — the default map is
      `sprites`, `e2b` and `daytona` only, so `Managoat.Sandbox` raises
      "unknown sandbox provider :runner" on the first handle built for a
      local box. The runner is a `Managoat.Sandbox` adapter that ships in a
      different package, so no default could have included it.

  An existing setting is left alone in both cases, so a consumer that names
  its own host or its own adapter map keeps it.
  """
  @spec configure() :: module()
  def configure do
    register_adapter()

    case Application.get_env(:managoat_runner, :host) do
      nil ->
        Application.put_env(:managoat_runner, :host, Local)
        Local

      configured ->
        configured
    end
  end

  defp register_adapter do
    adapters = Sandbox.adapters()

    unless Map.has_key?(adapters, :runner) do
      Application.put_env(
        :managoat_sandbox,
        :adapters,
        Map.put(adapters, :runner, Adapter)
      )
    end
  end

  @doc "The host module in force."
  @spec module() :: module()
  def module, do: Config.host!()

  @doc "Every runner currently connected, with the `meta` it registered with."
  @spec online() :: [{String.t(), map()}]
  def online, do: module().online()

  @doc "The connection process for a runner id, or `nil`."
  @spec whereis(String.t()) :: pid() | nil
  def whereis(runner_id) when is_binary(runner_id), do: module().whereis(runner_id)
end
