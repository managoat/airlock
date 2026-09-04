defmodule Airlock.CLI do
  @moduledoc """
  The escript entry point.

  Only the commands M0 steps 1–3 can honestly support are here. There is no
  `run` command, because provisioning a box (steps 4–9) is not built and
  `CLAUDE.md`'s rule is that unbuilt behaviour is never described as
  existing — a `run` that fails at the first step would be exactly that.

      airlock check <policy.yaml>     parse a policy and show what it compiles to
      airlock broker <policy.yaml>    start the broker and print the egress log
      airlock version
  """

  alias Airlock.Broker
  alias Airlock.Egress
  alias Airlock.Policy
  alias Airlock.Render

  @doc false
  @spec main([String.t()]) :: :ok | no_return()
  def main(argv) do
    case Airlock.Boot.boot() do
      :ok -> dispatch(argv)
      {:error, reason} -> die("airlock could not start: #{inspect(reason)}")
    end
  end

  defp dispatch(["check", path]), do: check(path)
  defp dispatch(["broker", path]), do: broker(path)
  defp dispatch(["version"]), do: out(Airlock.version())
  defp dispatch([]), do: out(@moduledoc)
  defp dispatch(["help" | _]), do: out(@moduledoc)
  defp dispatch(["--help" | _]), do: out(@moduledoc)
  defp dispatch(argv), do: die("airlock: no such command: #{Enum.join(argv, " ")}")

  # ── check ──────────────────────────────────────────────────────────────────

  defp check(path) do
    case Policy.load(path) do
      {:ok, policy} ->
        out(Render.policy(policy, path))
        report_missing(policy)

      {:error, reason} ->
        die(Render.error(reason, path))
    end
  end

  # A policy that parses can still be unrunnable, and the two are different
  # failures: the first is a mistake in the file, the second is a variable
  # that is not set in this shell. `check` reports the second without
  # failing, so it stays useful for reading a policy on a machine that does
  # not hold the credentials.
  defp report_missing(policy) do
    case Enum.reject(Policy.required_vars(policy), &System.get_env/1) do
      [] -> :ok
      missing -> out("\nNot set here: #{Enum.join(missing, ", ")}")
    end
  end

  # ── broker ─────────────────────────────────────────────────────────────────

  defp broker(path) do
    with {:ok, policy} <- Policy.load(path),
         {:ok, broker} <- Broker.start_link(policy: policy, supervisor: nil),
         {:ok, _egress} <- Egress.start_link(run: broker.run, schemes: broker.schemes) do
      out(Render.broker(broker, policy))
      follow(broker.run, 0)
    else
      {:error, reason} -> die(Render.error(reason, path))
    end
  end

  # Poll rather than subscribe: `Airlock.Egress` is the subscriber and this
  # is a terminal reading its rows. The record proper (M2) is a file.
  defp follow(run, seen) do
    rows = Egress.rows(run)

    case length(rows) - seen do
      0 ->
        :ok

      _new ->
        rows |> Enum.drop(seen) |> Enum.each(&out(Render.row(&1)))
    end

    Process.sleep(400)
    follow(run, length(rows))
  end

  # ── output ─────────────────────────────────────────────────────────────────

  defp out(text), do: IO.puts(text)

  @spec die(String.t()) :: no_return()
  defp die(text) do
    IO.puts(:stderr, text)
    System.halt(1)
  end
end
