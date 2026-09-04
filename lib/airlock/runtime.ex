defmodule Airlock.Runtime do
  @moduledoc """
  M0 step 5: one of the four coding agents onto the box, with the inference
  credential delivered as a **placeholder** rather than the real value, and
  the proxy environment pointing at the broker.

  This is the step the product's claim rests on. Everything else is
  plumbing; this is the line where the credential stops travelling.

  ## The substitution

  `Managoat.Runtimes` hands each runtime a map of inference credentials and
  the runtime decides which environment variable carries which — a Google
  key is `GEMINI_API_KEY` for gemini and `GOOGLE_GENERATIVE_AI_API_KEY` for
  opencode, and codex ignores the process environment entirely and logs in
  over stdin. Airlock does not need to know any of that. It puts the
  **placeholder** where the value would go and lets the runtime deliver it
  wherever it delivers credentials:

      credentials(%{"ANTHROPIC_API_KEY" => "PLACEHOLDER-ANTHROPIC"})
      #=> %{anthropic_api_key: "PLACEHOLDER-ANTHROPIC"}

  The agent then sends that placeholder believing it is a key, the broker
  substitutes the real one, and the origin sees a credential that was never
  on the box. `Airlock.BrokerTest` pins the proxy half of that; this module
  is the delivery half.

  ## Every placeholder, not the one we picked

  `credentials/1` passes through every `:substitute` entry the policy
  declares. `Managoat.Runtimes.Claude.default_env/2` deliberately exports
  exactly one of `CLAUDE_CODE_OAUTH_TOKEN` and `ANTHROPIC_API_KEY` — but
  `Claude.fall_back_to_api_key/2` can swap them on a box that is already
  running, when an org refuses the OAuth token mid-conversation. A broker
  session minted with only the first placeholder cannot serve the second,
  which is why `Airlock.Policy.Compile.placeholders/1` returns all of them
  and why the schema is a list.

  ## The optional callbacks are dispatched, never guarded

  `Managoat.Runtimes.default_env/3`, `write_config/3` and
  `prepare_sandbox/4` load the module first and fall back to the documented
  no-op. Writing `function_exported?/3` against them is the trap
  `CLAUDE.md` records twice and `managoat_runtimes` 0.3.0 exists to close —
  in goatherd it dropped the entire inference credential env and reported
  every stage green.

  ## Ordering

  `install/4` runs `npm install -g` through `Managoat.Runtimes.ACP.install/3`,
  so it must happen **before** `Airlock.Box.seal/3`. `Airlock.Run` is what
  guarantees that; this module only refuses to pretend otherwise.
  """

  alias Managoat.Runtimes
  alias Managoat.Sandbox

  # The credential keys the four runtimes actually read, from
  # `Managoat.Runtimes`' own sources. A fixed table rather than
  # `String.to_atom/1` on whatever a policy file names: a policy is user
  # input and the atom table is not garbage collected.
  @credential_keys %{
    "ANTHROPIC_API_KEY" => :anthropic_api_key,
    "CLAUDE_CODE_OAUTH_TOKEN" => :claude_code_oauth_token,
    "OPENAI_API_KEY" => :openai_api_key,
    "GEMINI_API_KEY" => :gemini_api_key,
    "GOOGLE_GENERATIVE_AI_API_KEY" => :gemini_api_key
  }

  @doc """
  Turn a policy's placeholders into the inference-credential map
  `Managoat.Runtimes` takes.

  A placeholder for a variable no runtime reads is dropped: it still
  reaches the box through `Airlock.Broker.box_env/1` as a plain
  environment variable, it just is not one the runtime will deliver for
  you.
  """
  @spec credentials(%{optional(String.t()) => String.t()}) :: %{atom() => String.t()}
  def credentials(placeholders) when is_map(placeholders) do
    for {name, placeholder} <- placeholders,
        key = Map.get(@credential_keys, name),
        not is_nil(key),
        into: %{},
        do: {key, placeholder}
  end

  @doc "The variable names a runtime can deliver a credential for."
  @spec deliverable_vars() :: [String.t()]
  def deliverable_vars, do: @credential_keys |> Map.keys() |> Enum.sort()

  @doc """
  The environment every command on the box runs with: the proxy and the
  placeholders from `Airlock.Broker.box_env/1`, then the runtime's own
  credential variables.

  Credentials last, so nothing earlier can shadow the variable the run
  authenticates with — the precedence goatherd's `sprite_env/4` settled,
  though for the opposite payload: goatherd lifts real secrets from the
  local shell *into* the box, and this puts placeholders there instead.

  Returns the `[{name, value}]` pairs `Managoat.Sandbox` takes.
  """
  @spec env(module(), Runtimes.agent(), %{optional(String.t()) => String.t()}, map()) ::
          [{String.t(), String.t()}]
  def env(runtime_mod, agent, box_env, placeholders) do
    credentials = Runtimes.default_env(runtime_mod, agent, credentials(placeholders))

    (Enum.to_list(box_env) ++ credentials)
    |> Enum.reverse()
    |> Enum.uniq_by(&elem(&1, 0))
    |> Enum.reverse()
  end

  @doc """
  Install the ACP adapter, the instructions file and the runtime's own
  config onto the box.

  **Reaches the network** — `npm install -g` for claude and codex, and
  `bun install` inside `OpenCode.prepare_sandbox/3`. Call it before the
  seal.
  """
  @spec install(Airlock.Box.t(), String.t(), Runtimes.agent(), [{String.t(), String.t()}]) ::
          :ok | {:error, term()}
  def install(box, runtime, agent, env) do
    with {:ok, runtime_mod} <- Runtimes.for_runtime(runtime),
         :ok <- Runtimes.ACP.install(box.handle, runtime, env),
         :ok <- Runtimes.write_config(runtime_mod, box.handle, agent),
         :ok <- Runtimes.Instructions.write(box.handle, runtime, instructions_agent(agent)) do
      Runtimes.prepare_sandbox(runtime_mod, box.handle, agent, env)
    end
  end

  @doc """
  Spawn the ACP adapter and return the `Managoat.Sandbox.Command` its
  stdout reaches the caller through.

  `detachable: true` is goatherd's finding 1 and it is why Airlock needs no
  session database: the adapter keeps running in the sandbox when the
  driving process exits, so resuming is a fresh connection rather than
  restored state.
  """
  @spec spawn(Airlock.Box.t(), String.t(), [{String.t(), String.t()}]) ::
          {:ok, Sandbox.Command.t()} | {:error, term()}
  def spawn(box, runtime, env) do
    {bin, args} = Runtimes.ACP.command(runtime)

    case Sandbox.spawn(box.handle, bin, args,
           owner: self(),
           env: env,
           dir: Sandbox.host_path(box.handle, Runtimes.ACP.cwd(runtime)),
           stdin: true,
           detachable: true
         ) do
      {:ok, command} -> {:ok, command}
      {:error, reason} -> {:error, {:adapter_spawn, reason}}
    end
  end

  @doc "The runtimes that can speak ACP, which is all Airlock supports."
  @spec supported() :: [String.t()]
  def supported, do: Runtimes.ACP.supported_runtimes()

  # `Instructions.write/3` only writes when the agent carries a `:system`,
  # so an agent with no system prompt correctly writes no file.
  defp instructions_agent(%{system: system} = agent) when is_binary(system), do: agent
  defp instructions_agent(_agent), do: nil
end
