defmodule Airlock.Box do
  @moduledoc """
  A machine, brought up under a policy and then sealed.

  M0 steps 4, 6 and 9. Step 5 — the runtime and its placeholders — is
  `Airlock.Runtime`, and the turn is `Airlock.Run`.

  ## The ordering is the whole thing

  `PLAN.md` calls the seal "the step with no prior art", and what makes it
  hard is not applying the policy, it is everything that has to have
  happened first:

      create ──▶ packages ──▶ adapter (npm) ──▶ skills ──▶ config ──▶ SEAL ──▶ turn
                └──────────── the network is open here ────────────┘

  Three things reach the network during provisioning and none of them can
  be moved after the seal:

    * `apt-get` cannot reach the archives once egress is default-deny;
    * `Managoat.Runtimes.ACP.install/3` runs `npm install -g`. Its own
      moduledoc says so and names the exposure: on a restricted sandbox
      "the allowlist has to include the npm registry, or the adapter
      install fails here";
    * `Managoat.Runtimes.Skills` installs over npm and GitHub.

  So the seal is last, and `seal/2` refuses to run twice or to run before
  the box has been provisioned — because a seal that silently did nothing
  is the failure this product cannot survive.

  ## What the seal permits

  `Airlock.Policy.Compile.network_policy/2`: the broker's host, and nothing
  else. The reasoning is in that module. The consequence here is that
  `seal/2` needs the address **the box** reaches the broker by, which is
  not the address the broker is bound to as soon as the box is not local —
  see `Airlock.Broker.Reachability`.

  ## Not every box can be sealed

  `Managoat.Runner.Adapter` refuses `apply_network_policy/2` outright. That
  is not a transient error and it is not something to retry or warn about
  and continue: a run that believes it is contained and is not is worse
  than a run that stops. `seal/2` returns `{:error, {:cannot_seal,
  provider}}` and `Airlock.Run` treats it as fatal unless the caller has
  said `--unsealed` in as many words.

  `NOTES-M0.md` §1 has the reasoning and the options.
  """

  alias Airlock.Box.Host
  alias Airlock.Policy
  alias Airlock.Policy.Compile
  alias Managoat.Runner.Names
  alias Managoat.Sandbox
  alias Managoat.Sandbox.Handle

  @type t :: %__MODULE__{
          handle: Handle.t(),
          provider: atom(),
          name: String.t(),
          sealed?: boolean()
        }

  @enforce_keys [:handle, :provider, :name]
  defstruct [:handle, :provider, :name, sealed?: false]

  @type stage :: (String.t(), :started | :done | {:failed, term()} -> any())

  @doc """
  Create a box and install what needs the network, **unsealed**.

  Options:

    * `:provider` — default `:sprites`;
    * `:name` — default a fresh one, in the shape the provider requires.
      A box is per-job and destroyed after it (`PLAN.md`'s settled question
      4), so a name is not something a user needs to choose;
    * `:packages` — `%{"apt" => [...], "npm" => [...]}`, run before
      anything else for the reason in the moduledoc;
    * `:env` — the environment every provisioning command runs with;
    * `:on_stage` — progress callback.
  """
  @spec provision(keyword()) :: {:ok, t()} | {:error, term()}
  def provision(opts \\ []) do
    provider = Keyword.get(opts, :provider, :sprites)
    env = Keyword.get(opts, :env, [])
    on_stage = Keyword.get(opts, :on_stage, fn _stage, _status -> :ok end)

    with {:ok, name} <- name_for(provider, Keyword.get(opts, :name)),
         {:ok, handle} <- stage(on_stage, "create", fn -> Sandbox.create(provider, name) end),
         box = %__MODULE__{handle: handle, provider: provider, name: name},
         :ok <-
           stage(on_stage, "packages", fn ->
             packages(box, Keyword.get(opts, :packages, %{}), env)
           end) do
      {:ok, box}
    end
  end

  @doc """
  Seal the box: apply the policy's egress list, which names the broker and
  nothing else.

  This is the last thing before the agent runs. It refuses a box it has
  already sealed, and a provider that cannot be sealed.
  """
  @spec seal(t(), Policy.t(), String.t()) :: {:ok, t()} | {:error, term()}
  def seal(%__MODULE__{sealed?: true}, _policy, _broker_host), do: {:error, :already_sealed}

  def seal(%__MODULE__{} = box, %Policy{} = policy, broker_host) when is_binary(broker_host) do
    if sealable?(box.provider) do
      network_policy = Compile.network_policy(policy, broker_host)

      case Sandbox.apply_network_policy(box.handle, network_policy) do
        :ok -> {:ok, %{box | sealed?: true}}
        {:error, reason} -> {:error, {:seal_failed, reason}}
      end
    else
      {:error, {:cannot_seal, box.provider}}
    end
  end

  @doc """
  Can this provider's boxes have a network policy applied at all?

  Asked of the adapter rather than hardcoded, so a provider that grows the
  capability is picked up without a change here — and so a provider that
  loses it is not silently trusted.
  """
  @spec sealable?(atom()) :: boolean()
  def sealable?(provider) when is_atom(provider) do
    Sandbox.supports?(provider, :network_policy)
  end

  @doc """
  Destroy the box. M0 step 9, and settled question 4: a box is per-job, so
  a run's record describes a box nothing else touched.

  Already-gone is success, which is the `Managoat.Sandbox` contract.
  """
  @spec destroy(t()) :: :ok | {:error, term()}
  def destroy(%__MODULE__{handle: handle}), do: Sandbox.destroy(handle)

  @doc "Run a command on the box."
  @spec exec(t(), String.t(), [String.t()], keyword()) ::
          {:ok, String.t(), integer()} | {:error, term()}
  def exec(%__MODULE__{handle: handle}, cmd, args, opts \\ []) do
    Sandbox.exec(handle, cmd, args, opts)
  end

  # ── provisioning stages ────────────────────────────────────────────────────

  defp packages(_box, packages, _env) when packages == %{} or is_nil(packages), do: :ok

  defp packages(box, packages, env) do
    apt = packages |> Map.get("apt", []) |> List.wrap()
    npm = packages |> Map.get("npm", []) |> List.wrap()

    # `apt-get` after the seal cannot reach the archives, which is why this
    # is the first stage rather than a convenience.
    scripts =
      Enum.reject(
        [
          apt != [] &&
            "sudo apt-get update -qq && sudo apt-get install -y -qq #{Enum.join(apt, " ")}",
          npm != [] && "npm install -g --no-progress --silent #{Enum.join(npm, " ")}"
        ],
        &(&1 == false)
      )

    Enum.reduce_while(scripts, :ok, fn script, :ok ->
      case exec(box, "bash", ["-lc", script], env: env, timeout: 300_000) do
        {:ok, _out, 0} -> {:cont, :ok}
        {:ok, out, code} -> {:halt, {:error, {:exit, code, tail(out)}}}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
  end

  defp stage(on_stage, name, fun) do
    on_stage.(name, :started)

    case fun.() do
      :ok ->
        on_stage.(name, :done)
        :ok

      {:ok, value} ->
        on_stage.(name, :done)
        {:ok, value}

      {:error, reason} ->
        on_stage.(name, {:failed, reason})
        {:error, {String.to_atom(name), reason}}
    end
  end

  @doc """
  A fresh sandbox name in the shape `provider` requires.

  Only the runner constrains it, and it constrains it absolutely: a name
  is the *only* thing `Managoat.Sandbox` hands an adapter, so the runner
  carries the runner id inside it (`runner-<32 hex>-<8 hex>`) and refuses
  anything else with `{:invalid, {:not_a_runner_sandbox_name, name}}`.
  Which runner a new sandbox lands on is the host's placement policy and
  `Managoat.Runner.Names` deliberately does not decide it — so this does,
  by taking the one that is connected.
  """
  @spec name_for(atom(), String.t() | nil) :: {:ok, String.t()} | {:error, term()}
  def name_for(_provider, name) when is_binary(name), do: {:ok, name}

  def name_for(:runner, nil) do
    case Host.online() do
      [{runner_id, _meta} | _rest] -> {:ok, Names.for_runner(runner_id)}
      [] -> {:error, :no_runner_connected}
    end
  end

  def name_for(_provider, nil), do: {:ok, generate_name()}

  defp generate_name,
    do: "airlock-" <> (8 |> :crypto.strong_rand_bytes() |> Base.encode16(case: :lower))

  defp tail(output), do: output |> to_string() |> String.slice(-500..-1//1) |> to_string()
end
