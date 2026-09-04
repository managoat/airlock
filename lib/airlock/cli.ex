defmodule Airlock.CLI do
  @moduledoc """
  The escript entry point.

      airlock run <policy.yaml> <prompt>   run one job on a box and print the record
      airlock check <policy.yaml>          parse a policy and show what it compiles to
      airlock broker <policy.yaml>         start the broker and print the egress log
      airlock version

  `run` options:

      --runtime claude|codex|gemini|opencode   default claude
      --provider sprites|e2b|daytona|runner    default sprites
      --broker-host <host:port>                the address the BOX reaches the broker by
      --timeout <seconds>                      default 600
      --unsealed                               proceed on a box that cannot be sealed

  ## `--broker-host` is required for a cloud box, and there is no default

  The broker is a listener the box dials out to, so a box on someone else's
  hardware needs an address on *their* network. `Airlock.Broker.Reachability`
  refuses a loopback address for a cloud provider before anything is
  created, because left alone it fails after provisioning and looks exactly
  like an agent that made no requests.

  A raw TCP tunnel works — the proxy protocol is `CONNECT` and
  absolute-form HTTP, which an HTTP reverse proxy will not forward:

      ngrok tcp 14322      # then --broker-host 4.tcp.ngrok.io:19482

  Read `Airlock.Broker.Reachability` before pointing a real credential
  through one: the listener is plaintext and the session token rides in the
  clear.
  """

  alias Airlock.Broker
  alias Airlock.Broker.Reachability
  alias Airlock.Egress
  alias Airlock.Policy
  alias Airlock.Render
  alias Airlock.Run

  @doc false
  @spec main([String.t()]) :: :ok | no_return()
  def main(argv) do
    case Airlock.Boot.boot() do
      :ok -> dispatch(argv)
      {:error, reason} -> die("airlock could not start: #{inspect(reason)}")
    end
  end

  defp dispatch(["run", path, prompt | flags]), do: run(path, prompt, flags)
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

  # ── run ────────────────────────────────────────────────────────────────────

  defp run(path, prompt, flags) do
    with {:ok, opts} <- parse_flags(flags),
         {:ok, policy} <- Policy.load(path) do
      provider = opts[:provider]
      broker_host = opts[:broker_host]

      if broker_host, do: warn(Reachability.warning(broker_host, provider))

      started =
        Run.start(
          [policy: policy, prompt: prompt, on_stage: &Render.stage/2] ++
            Keyword.delete(opts, :broker_host) ++ broker_host_opt(broker_host)
        )

      case started do
        {:ok, result} -> out(Render.record(result))
        {:error, reason} -> die(Render.run_error(reason, path))
      end
    else
      {:error, reason} -> die(Render.error(reason, path))
    end
  end

  defp broker_host_opt(nil), do: []
  defp broker_host_opt(host), do: [broker_host: host]

  @flags [
    runtime: :string,
    provider: :string,
    broker_host: :string,
    timeout: :integer,
    unsealed: :boolean
  ]

  @providers ~w(sprites e2b daytona runner)

  defp parse_flags(flags) do
    {parsed, rest, invalid} = OptionParser.parse(flags, strict: @flags)

    cond do
      invalid != [] -> {:error, {:bad_flags, Enum.map(invalid, &elem(&1, 0))}}
      rest != [] -> {:error, {:unexpected_args, rest}}
      true -> normalise_flags(parsed)
    end
  end

  defp normalise_flags(parsed) do
    provider = Keyword.get(parsed, :provider, "sprites")

    if provider in @providers do
      {:ok,
       [
         runtime: Keyword.get(parsed, :runtime, "claude"),
         provider: String.to_existing_atom(provider),
         unsealed: Keyword.get(parsed, :unsealed, false),
         timeout: Keyword.get(parsed, :timeout, 600) * 1000,
         broker_host: Keyword.get(parsed, :broker_host)
       ]}
    else
      {:error, {:bad_provider, provider, @providers}}
    end
  end

  defp warn(nil), do: :ok
  defp warn(text), do: IO.puts(:stderr, "\n" <> text <> "\n")

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
