defmodule Airlock.Test.FakeBox do
  @moduledoc """
  `Managoat.Sandbox.Fake` with a shell that answers instead of raising.

  ## Why this exists

  The Fake's commands speak a scripted vocabulary — `out:`, `err:`,
  `exit:`, `stay`, `drop` — and **any other argv raises**:

      ** (FunctionClauseError) no function clause matching in
         anonymous fn/1 in Managoat.Sandbox.Fake.script/1
      # 1
      "-lc"

  That collides with one of the three jobs its own moduledoc claims, "drive
  a provisioning path without a network", because every real provisioning
  step is `bash -lc <script>`: `Managoat.Runtimes.ACP.install/3`'s npm
  install, `Gemini.prepare_sandbox/3`, `OpenCode`'s bun install, and
  `Airlock.Box`'s apt stage. The first one raises and the run dies with a
  `FunctionClauseError` from inside the library rather than an error a
  caller can read.

  So this adapter delegates everything to the Fake and makes `exec/4`
  total: an argv the Fake's vocabulary understands is passed through, and
  anything else is a command that ran and exited 0. That is what a box
  does, and it is what lets `Airlock.RunTest` exercise the real ordering —
  provision, npm, **seal**, turn — including the seal, which the Fake
  genuinely applies and `Managoat.Sandbox.Fake.policy/1` reports.

  Reported upstream. It is test support, not something Airlock ships, and
  it should be deleted when the Fake handles an unknown argv itself.

  ## What it does not fake

  A shell. Nothing here interprets the script — a provisioning step that
  depends on its own side effects will not see them. The ordering is what
  is under test, not the commands.
  """

  @behaviour Managoat.Sandbox

  alias Managoat.Sandbox.Fake
  alias Managoat.Sandbox.Handle

  # The Fake's own instruction set. Anything else is a real command as far
  # as this adapter is concerned.
  @scripted ~w(stay drop)

  @impl true
  def provider, do: :fake_box

  @impl true
  def capabilities, do: Fake.capabilities()

  @impl true
  def build_handle(name) when is_binary(name), do: %Handle{provider: :fake_box, name: name}

  @impl true
  def create(name, opts) do
    with {:ok, handle} <- Fake.create(name, opts), do: {:ok, %{handle | provider: :fake_box}}
  end

  @impl true
  def get(handle), do: Fake.get(fake(handle))

  @impl true
  def destroy(handle), do: Fake.destroy(fake(handle))

  @impl true
  def list_all_names, do: Fake.list_all_names()

  @impl true
  def suspend(handle), do: Fake.suspend(fake(handle))

  @impl true
  def resume(handle) do
    with {:ok, resumed} <- Fake.resume(fake(handle)), do: {:ok, %{resumed | provider: :fake_box}}
  end

  @impl true
  def public_url(handle), do: Fake.public_url(fake(handle))

  @impl true
  def write_file(handle, path, data, opts), do: Fake.write_file(fake(handle), path, data, opts)

  @impl true
  def exec(handle, cmd, args, opts) do
    if scripted?(args) do
      Fake.exec(fake(handle), cmd, args, opts)
    else
      {:ok, "", 0}
    end
  end

  @impl true
  def spawn(handle, cmd, args, opts) do
    args = if scripted?(args), do: args, else: ["stay"]

    with {:ok, command} <- Fake.spawn(fake(handle), cmd, args, opts) do
      {:ok, %{command | provider: :fake_box}}
    end
  end

  @impl true
  def write_stdin(command, data), do: Fake.write_stdin(fake(command), data)

  @impl true
  def close_stdin(command), do: Fake.close_stdin(fake(command))

  @impl true
  def stop_command(command), do: Fake.stop_command(fake(command))

  @impl true
  def list_sessions(handle), do: Fake.list_sessions(fake(handle))

  @impl true
  def attach(handle, session_id, opts), do: Fake.attach(fake(handle), session_id, opts)

  @impl true
  def apply_network_policy(handle, policy), do: Fake.apply_network_policy(fake(handle), policy)

  @impl true
  def create_checkpoint(handle, opts), do: Fake.create_checkpoint(fake(handle), opts)

  @impl true
  def restore_checkpoint(handle, id), do: Fake.restore_checkpoint(fake(handle), id)

  # The Fake keys its state on the name and never reads the provider, but
  # its heads match on the struct, so hand it one that says `:fake`.
  defp fake(%Handle{} = handle), do: %{handle | provider: :fake}
  defp fake(%Managoat.Sandbox.Command{} = command), do: %{command | provider: :fake}

  defp scripted?(args) when is_list(args) do
    Enum.all?(args, fn arg ->
      is_binary(arg) and
        (arg in @scripted or String.starts_with?(arg, ["out:", "err:", "exit:"]))
    end)
  end

  defp scripted?(_args), do: false
end

defmodule Airlock.Test.UnsealableBox do
  @moduledoc """
  `Airlock.Test.FakeBox` with the seal taken away, exactly as
  `Managoat.Runner.Adapter` has it: `:network_policy` is not advertised and
  `apply_network_policy/2` returns `{:error, :not_supported}`.

  A stand-in for the runner rather than the runner itself, because the
  runner refuses to *create* a sandbox whose name is not
  `runner-<32 hex>-<8 hex>` — so a run on it never reaches the seal, and a
  test using it would pass for the wrong reason.
  """

  @behaviour Managoat.Sandbox

  alias Airlock.Test.FakeBox
  alias Managoat.Sandbox.Handle

  @impl true
  def provider, do: :unsealable

  # Written out rather than `MapSet.delete(FakeBox.capabilities(), …)`:
  # `MapSet.t/0` is opaque, so deleting from another module's set is a
  # dialyzer violation. This is the Fake's set minus the seal.
  @impl true
  def capabilities, do: MapSet.new([:suspend, :attach, :public_url])

  @impl true
  def build_handle(name) when is_binary(name), do: %Handle{provider: :unsealable, name: name}

  @impl true
  def apply_network_policy(%Handle{}, _policy), do: {:error, :not_supported}

  @impl true
  def create(name, opts) do
    with {:ok, handle} <- FakeBox.create(name, opts), do: {:ok, rebrand(handle)}
  end

  @impl true
  def resume(handle) do
    with {:ok, resumed} <- FakeBox.resume(box(handle)), do: {:ok, rebrand(resumed)}
  end

  @impl true
  def spawn(handle, cmd, args, opts) do
    with {:ok, command} <- FakeBox.spawn(box(handle), cmd, args, opts) do
      {:ok, %{command | provider: :unsealable}}
    end
  end

  @impl true
  def get(handle), do: FakeBox.get(box(handle))
  @impl true
  def destroy(handle), do: FakeBox.destroy(box(handle))
  @impl true
  def list_all_names, do: FakeBox.list_all_names()
  @impl true
  def suspend(handle), do: FakeBox.suspend(box(handle))
  @impl true
  def public_url(handle), do: FakeBox.public_url(box(handle))
  @impl true
  def write_file(handle, path, data, opts), do: FakeBox.write_file(box(handle), path, data, opts)
  @impl true
  def exec(handle, cmd, args, opts), do: FakeBox.exec(box(handle), cmd, args, opts)
  @impl true
  def write_stdin(command, data), do: FakeBox.write_stdin(box(command), data)
  @impl true
  def close_stdin(command), do: FakeBox.close_stdin(box(command))
  @impl true
  def stop_command(command), do: FakeBox.stop_command(box(command))
  @impl true
  def list_sessions(handle), do: FakeBox.list_sessions(box(handle))
  @impl true
  def attach(handle, session_id, opts), do: FakeBox.attach(box(handle), session_id, opts)
  @impl true
  def create_checkpoint(handle, opts), do: FakeBox.create_checkpoint(box(handle), opts)
  @impl true
  def restore_checkpoint(handle, id), do: FakeBox.restore_checkpoint(box(handle), id)

  defp box(%Handle{} = handle), do: %{handle | provider: :fake_box}
  defp box(%Managoat.Sandbox.Command{} = command), do: %{command | provider: :fake_box}

  defp rebrand(%Handle{} = handle), do: %{handle | provider: :unsealable}
end
