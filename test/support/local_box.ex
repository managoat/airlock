defmodule Airlock.Test.LocalBox do
  @moduledoc """
  `Airlock.Test.FakeBox` with a real shell behind `exec/4`.

  ## Why this exists

  `Airlock.Changes` is three bash scripts and two parsers, and the scripts
  are the half that can be wrong in ways a fake cannot show: a pathspec
  that excludes nothing, a `-z` record shape that is not what git emits, a
  pipeline whose exit status is `base64`'s rather than `git`'s. Every one
  of those passes against a box that answers every command with exit 0,
  which is what `FakeBox` does and has to do.

  So this adapter runs the argv, on this machine, with `System.cmd/3`. The
  tests that use it hand `Airlock.Changes` a real temporary directory as
  the workspace and let it `git init` there, so what is under test is the
  script talking to the git that is installed.

  **Not a sandbox and not a box.** There is no isolation here whatsoever —
  it is `System.cmd` — so it is only ever used with a path the test made
  and cleans up, and it is test support rather than something Airlock
  ships. `Managoat.Sandbox.Fake` remains the adapter for everything that
  is about the *ordering* rather than the commands.
  """

  @behaviour Managoat.Sandbox

  alias Airlock.Test.FakeBox
  alias Managoat.Sandbox.Handle

  @impl true
  def provider, do: :local_box

  @impl true
  def capabilities, do: FakeBox.capabilities()

  @impl true
  def build_handle(name) when is_binary(name), do: %Handle{provider: :local_box, name: name}

  @impl true
  def exec(_handle, cmd, args, opts) do
    {output, code} =
      System.cmd(cmd, args,
        stderr_to_stdout: false,
        env: Enum.map(Keyword.get(opts, :env, []), fn {k, v} -> {to_string(k), to_string(v)} end)
      )

    {:ok, output, code}
  rescue
    error -> {:error, error}
  end

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
      {:ok, %{command | provider: :local_box}}
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
  def apply_network_policy(handle, policy), do: FakeBox.apply_network_policy(box(handle), policy)
  @impl true
  def create_checkpoint(handle, opts), do: FakeBox.create_checkpoint(box(handle), opts)
  @impl true
  def restore_checkpoint(handle, id), do: FakeBox.restore_checkpoint(box(handle), id)

  defp box(%Handle{} = handle), do: %{handle | provider: :fake_box}
  defp box(%Managoat.Sandbox.Command{} = command), do: %{command | provider: :fake_box}

  defp rebrand(%Handle{} = handle), do: %{handle | provider: :local_box}
end
