defmodule Airlock.Run do
  @moduledoc """
  One job, start to finish: M0 steps 4 through 9.

      broker ─▶ box ─▶ runtime ─▶ SEAL ─▶ turn ─▶ record ─▶ destroy

  ## Why this is not goatherd's `driver.ex`

  `CLAUDE.md` says its reasoning does not transfer, and having written both
  halves the difference is concrete. goatherd's driver argues it should be
  the CLI process rather than a GenServer, because there is one turn per
  invocation and the terminal is its only consumer. Here:

    * there is a second consumer — `Airlock.Egress` is collecting rows for
      the same run, from a telemetry handler, on its own process;
    * there is a persisted artefact, the record, which outlives the turn;
    * the broker session brackets the turn on both sides: it is minted
      before the box exists and it is what the seal is written in terms of.

  So the run owns a lifetime rather than a turn, and the ordering below is
  the thing it exists to guarantee.

  ## The ordering, and why each step is where it is

  | | |
  |---|---|
  | 1. mint the broker session | the box's egress policy names the broker, so the broker's address has to exist before the box can be sealed |
  | 2. check reachability | before anything is created, because pointing a cloud box at loopback fails *after* provisioning and looks like an agent that made no requests |
  | 3. provision, unsealed | apt reaches the archives |
  | 4. install the runtime | `npm install -g`, so still before the seal |
  | 5. **seal** | last, and fatal if it fails |
  | 6. the turn | `Managoat.ACP.Peer` |
  | 7. the record | transcript and egress rows |
  | 8. destroy | per-job box, settled question 4 |

  Steps 3 and 4 are the ones that must not move. `PLAN.md` says so and
  `Managoat.Runtimes.ACP.install/3`'s own moduledoc says so again from the
  other side.

  ## Provisioning does not go through the broker

  The box gets the proxy environment for the **turn**, not for
  provisioning. Two reasons, and the first is decisive:

    * `npm install -g` for the ACP adapter would otherwise go through the
      proxy, and a `deny` session refuses `registry.npmjs.org` unless the
      policy names it. That would make every policy carry Airlock's own
      implementation details — a user's allow list would have to include
      the npm registry to run an agent that never touches npm;
    * the box is not sealed yet, so nothing is being contained during
      provisioning and routing it through a chokepoint records Airlock's
      own installs rather than the agent's work.

  The consequence to be honest about: **provisioning egress is not in the
  record.** The record covers the sealed box, which is the agent's whole
  life. What provisioning fetched is `PLAN.md`'s step 4 by design — "still
  unsealed. Packages, skills and npm all reach the network here".

  ## The permission policy is set, never defaulted

  `Managoat.ACP.Permissions.verdict_for/2` falls back to **`auto_allow`**
  when a policy names nothing, and `Managoat.ACP.Peer` starts with
  `permission_policy: %{}`. So a peer started the obvious way approves
  every tool call the agent asks about, silently, and the
  `{:permission_ask, …}` report never reaches its owner.

  That is a reasonable default for an interactive product with a human in
  the loop. It is the wrong one here: M0 runs one prompt unattended, on a
  box holding a proxy address that reaches real credentials, and "allow
  everything nobody was asked about" is not a containment story.

  So the run names its policy. `:permission_policy` defaults to
  `%{"default" => "ask"}` — every request reaches this module, which denies
  it and records that it did, because there is nobody to ask. A caller that
  wants the agent to proceed unattended says
  `permission_policy: %{"default" => "auto_allow"}` and owns that choice.

  ## A seal that fails stops the run

  Not a warning. A run that believes it is contained and is not produces a
  record that is evidence of the wrong thing, and this is a containment
  product. `unsealed: true` is the only way past it and the caller has to
  say it in as many words; `Airlock.CLI` spells it `--unsealed` and prints
  what it means.
  """

  alias Airlock.Box
  alias Airlock.Broker
  alias Airlock.Broker.Reachability
  alias Airlock.Credentials
  alias Airlock.Egress
  alias Airlock.Policy
  alias Airlock.Policy.Compile
  alias Airlock.Runtime
  alias Airlock.Transcript
  alias Managoat.ACP.Peer
  alias Managoat.Runtimes
  alias Managoat.Sandbox

  @type result :: %{
          run: String.t(),
          transcript: Transcript.t(),
          egress: [map()],
          box: String.t(),
          sealed?: boolean(),
          provider: atom(),
          runtime: String.t(),
          prompt: String.t(),
          policy: Policy.t(),
          sealed_to: String.t(),
          started_at: DateTime.t(),
          finished_at: DateTime.t()
        }

  @default_timeout 600_000

  # Not `%{}`. See the moduledoc: an empty policy is auto-allow, which for
  # an unattended turn on a box holding a live proxy address is the wrong
  # way round.
  @default_permission_policy %{"default" => "ask"}

  @doc """
  Run one prompt on a fresh box under `policy`.

  Options:

    * `:policy` and `:prompt` — required;
    * `:runtime` — `"claude"`, `"codex"`, `"gemini"` or `"opencode"`;
    * `:broker_host` — the address **the box** reaches the broker by. For a
      local box this is loopback and the default is right; for a cloud box
      it is a tunnel or a deployment, and there is no default that could be;
    * `:provider` — default `:sprites`;
    * `:vars` — where `from: env:NAME` resolves. Defaults to the process
      environment plus whatever `Airlock.Credentials.inference_credentials/0`
      finds, so a policy naming `CLAUDE_CODE_OAUTH_TOKEN` resolves on a
      machine signed in to Claude Code without exporting anything. The
      environment wins on a clash;
    * `:unsealed` — proceed on a box that cannot be sealed. Default `false`;
    * `:agent` — the `Managoat.Runtimes.agent()` map (`:model`, `:system`,
      `:mcp_servers`);
    * `:permission_policy` — default `%{"default" => "ask"}`, which with
      nobody to ask means every request is denied and recorded. See the
      moduledoc: the library's own default is `auto_allow`;
    * `:on_stage` — progress callback;
    * `:timeout` — how long the turn may take, default ten minutes.
  """
  @spec start(keyword()) :: {:ok, result()} | {:error, term()}
  def start(opts) do
    policy = Keyword.fetch!(opts, :policy)
    prompt = Keyword.fetch!(opts, :prompt)
    runtime = Keyword.get(opts, :runtime, "claude")
    provider = Keyword.get(opts, :provider, :sprites)
    on_stage = Keyword.get(opts, :on_stage, fn _stage, _status -> :ok end)

    with :ok <- known_runtime(runtime),
         {:ok, broker} <- mint_broker(policy, opts),
         broker_host = broker_host(broker, opts),
         # Reachability first: it is about the invocation, and it is the
         # check that must run before anything is created. Credentials are
         # about the shell, and the library would raise for them anyway.
         :ok <- Reachability.check(broker_host, provider),
         :ok <- provider_ready(provider),
         {:ok, _egress} <- Egress.start_link(run: broker.run) do
      on_stage.("broker", {:ready, broker_host})

      result = provision_and_run(broker, broker_host, policy, prompt, runtime, provider, opts)
      Egress.detach(broker.run)
      result
    end
  end

  @doc """
  The address the box reaches the broker by.

  Defaults to what the broker bound to, which is right only when the box is
  on this machine. `Reachability.check/2` is what refuses the default
  everywhere else rather than letting it fail after provisioning.
  """
  @spec broker_host(Broker.t(), keyword()) :: String.t()
  def broker_host(%Broker{} = broker, opts) do
    Keyword.get(opts, :broker_host) || "#{broker.host}:#{broker.port}"
  end

  # ── the run ────────────────────────────────────────────────────────────────

  defp provision_and_run(broker, broker_host, policy, prompt, runtime, provider, opts) do
    agent = Keyword.get(opts, :agent, %{}) |> Map.put(:runtime, runtime)
    on_stage = Keyword.get(opts, :on_stage, fn _stage, _status -> :ok end)
    started_at = DateTime.utc_now()

    # Two environments, deliberately. Provisioning gets the placeholders
    # and the runtime's own variables but **not** the proxy; the turn gets
    # the proxy as well. See the moduledoc.
    proxy = proxy_env(broker, broker_host)

    with {:ok, runtime_mod} <- Runtimes.for_runtime(runtime),
         provision_env = Runtime.env(runtime_mod, agent, %{}, broker.placeholders),
         {:ok, box} <-
           Box.provision(
             provider: provider,
             env: provision_env,
             packages: Keyword.get(opts, :packages, %{}),
             on_stage: on_stage
           ) do
      result =
        after_provision(box, %{
          broker: broker,
          broker_host: broker_host,
          policy: policy,
          prompt: prompt,
          runtime: runtime,
          runtime_mod: runtime_mod,
          provider: provider,
          started_at: started_at,
          agent: agent,
          provision_env: provision_env,
          proxy: proxy,
          opts: opts
        })

      # Step 9, and it runs whatever happened above: a box that outlived a
      # failed run is a box holding a placeholder and a proxy address, and
      # settled question 4 says a box is per-job.
      on_stage.("destroy", :started)
      _ = Box.destroy(box)
      on_stage.("destroy", :done)

      result
    end
  end

  # Everything the run carries past provisioning, in one map: nine
  # positional arguments in a row is a shape nobody can call correctly.
  defp after_provision(box, ctx) do
    on_stage = Keyword.get(ctx.opts, :on_stage, fn _stage, _status -> :ok end)

    trust = fn -> Box.trust_ca(box, Broker.ca_pem(ctx.broker), ctx.provision_env) end
    install = fn -> Runtime.install(box, ctx.runtime, ctx.agent, ctx.provision_env) end

    with {:ok, ca_env} <- stage(on_stage, "trust", trust),
         :ok <- stage(on_stage, "runtime", install),
         {:ok, box} <- seal(box, ctx.policy, ctx.broker_host, on_stage, ctx.opts),
         turn_env = turn_env(ctx, ca_env),
         {:ok, transcript} <- turn(box, ctx.runtime, turn_env, ctx.prompt, ctx.agent, ctx.opts) do
      {:ok,
       %{
         run: ctx.broker.run,
         transcript: transcript,
         egress: Egress.rows(ctx.broker.run),
         box: box.name,
         sealed?: box.sealed?,
         provider: ctx.provider,
         runtime: ctx.runtime,
         prompt: ctx.prompt,
         policy: ctx.policy,
         # What the seal actually named, read off the compiled policy
         # rather than off the address that was asked for: `allow` is
         # domains, so the port the caller gave is not in it.
         sealed_to: sealed_to(ctx.policy, ctx.broker_host),
         started_at: ctx.started_at,
         finished_at: DateTime.utc_now()
       }}
    end
  end

  # `Compile.network_policy/2`'s allow list is always exactly one host, so
  # this destructures rather than defending: a fallback clause here would
  # be dead code claiming to handle a shape the compiler cannot produce.
  defp sealed_to(policy, broker_host) do
    %{allow: [host | _]} = Compile.network_policy(policy, broker_host)
    host
  end

  # What the agent runs with: the proxy, the trust store the broker's own
  # certificates need, the placeholders, and the runtime's credentials
  # last so nothing shadows them.
  defp turn_env(ctx, ca_env) do
    base = ctx.proxy |> Map.merge(ca_env) |> Map.merge(no_proxy())
    Runtime.env(ctx.runtime_mod, ctx.agent, base, ctx.broker.placeholders)
  end

  # A runtime talking to something on its own box does not go out through
  # the proxy.
  defp no_proxy,
    do: %{"NO_PROXY" => "localhost,127.0.0.1,::1", "no_proxy" => "localhost,127.0.0.1,::1"}

  # The last thing before the agent runs, and fatal by default. See the
  # moduledoc.
  defp seal(box, policy, broker_host, on_stage, opts) do
    on_stage.("seal", :started)

    case Box.seal(box, policy, broker_host) do
      {:ok, sealed} ->
        on_stage.("seal", :done)
        {:ok, sealed}

      {:error, {:cannot_seal, provider}} ->
        if Keyword.get(opts, :unsealed, false) do
          on_stage.("seal", {:skipped, provider})
          {:ok, box}
        else
          on_stage.("seal", {:failed, {:cannot_seal, provider}})
          {:error, {:cannot_seal, provider}}
        end

      {:error, reason} ->
        on_stage.("seal", {:failed, reason})
        {:error, reason}
    end
  end

  # ── the turn ───────────────────────────────────────────────────────────────

  defp turn(box, runtime, env, prompt, agent, opts) do
    on_stage = Keyword.get(opts, :on_stage, fn _stage, _status -> :ok end)
    on_stage.("turn", :started)

    with {:ok, command} <- Runtime.spawn(box, runtime, env),
         {:ok, peer} <- open_peer(command, runtime, prompt, agent, opts) do
      deadline =
        System.monotonic_time(:millisecond) + Keyword.get(opts, :timeout, @default_timeout)

      result =
        drive(%{command_ref: command.ref, peer: peer, transcript: Transcript.new()}, deadline)

      Peer.close(peer)

      case result do
        {:ok, _transcript} = ok ->
          on_stage.("turn", :done)
          ok

        {:error, reason} = error ->
          on_stage.("turn", {:failed, reason})
          error
      end
    end
  end

  defp open_peer(command, runtime, prompt, agent, opts) do
    Peer.start(
      owner: self(),
      writer: writer(command),
      ref: make_ref(),
      prompt: prompt,
      mode: :run,
      session_id: nil,
      cwd: Runtimes.ACP.cwd(runtime),
      model: Map.get(agent, :model),
      mcp_servers: Runtimes.ACP.mcp_servers(agent),
      permission_policy: Keyword.get(opts, :permission_policy, @default_permission_policy)
    )
  end

  @doc "The permission policy a run uses when the caller names none."
  @spec default_permission_policy() :: map()
  def default_permission_policy, do: @default_permission_policy

  # Total by contract: a command whose transport has gone answers
  # `{:error, _}` rather than raising, so the peer reports one failure
  # instead of dying with a turn in flight.
  defp writer(command), do: fn iodata -> Sandbox.write_stdin(command, iodata) end

  @doc """
  Drive one turn to its end, and return the transcript.

  Public because it is the piece worth testing on its own: it needs a peer
  and a command reference and nothing else, so
  `Managoat.ACP.Testing.ScriptedAgent` can play the agent and the whole
  loop runs without a box. That is the same seam
  `Managoat.ACP.Transport` documents — bytes in by cast, reports by
  message — rather than an injection point invented for a test.

  `ctx` is `%{command_ref:, peer:, transcript:}`; `deadline` is a
  `System.monotonic_time(:millisecond)` value.
  """
  @spec drive(map(), integer()) :: {:ok, Transcript.t()} | {:error, term()}
  def drive(ctx, deadline) do
    remaining = deadline - System.monotonic_time(:millisecond)

    if remaining <= 0 do
      {:error, {:turn_timeout, ctx.transcript}}
    else
      receive_one(ctx, deadline, remaining)
    end
  end

  defp receive_one(ctx, deadline, remaining) do
    ref = ctx.command_ref

    receive do
      {:stdout, %{ref: ^ref}, data} ->
        Peer.stdout(ctx.peer, data)
        drive(ctx, deadline)

      {:stderr, %{ref: ^ref}, data} ->
        drive(%{ctx | transcript: Transcript.add_stderr(ctx.transcript, data)}, deadline)

      {:exit, %{ref: ^ref}, code} ->
        {:error, {:adapter_exited, code, ctx.transcript.stderr}}

      {:error, %{ref: ^ref}, reason} ->
        {:error, {:transport, reason}}

      {:acp, _peer_ref, payload} ->
        case acp(ctx, payload) do
          {:cont, ctx} -> drive(ctx, deadline)
          {:halt, result} -> result
        end
    after
      remaining -> {:error, {:turn_timeout, ctx.transcript}}
    end
  end

  defp acp(ctx, {:lines, _stream, data}),
    do: {:cont, %{ctx | transcript: Transcript.add_line(ctx.transcript, data)}}

  defp acp(ctx, {:session, session_id}),
    do: {:cont, %{ctx | transcript: Transcript.put_session(ctx.transcript, session_id)}}

  defp acp(ctx, {:done, stop_reason, usage}),
    do: {:halt, {:ok, Transcript.finish(ctx.transcript, stop_reason, usage)}}

  defp acp(ctx, {:failed, reason}), do: {:halt, {:error, {:acp, reason, ctx.transcript.stderr}}}

  # opencode never asks for permission, and the other three do — but M0
  # runs one prompt unattended, so there is nobody to ask. Denying is the
  # honest answer: the agent is told no and the record shows it, rather
  # than the turn hanging on a question nothing will answer.
  defp acp(ctx, {:permission_ask, request_id, _tool, _options}) do
    Peer.deny_permission(ctx.peer, request_id)
    {:cont, ctx}
  end

  defp acp(ctx, _payload), do: {:cont, ctx}

  # ── setup ──────────────────────────────────────────────────────────────────

  defp mint_broker(policy, opts) do
    Broker.start_link(
      policy: policy,
      vars: Keyword.get_lazy(opts, :vars, &default_vars/0),
      name: Keyword.get(opts, :broker_name, Airlock.Broker.Listener),
      allow_private_upstreams: Keyword.get(opts, :allow_private_upstreams, false),
      port: Keyword.get(opts, :broker_port, 0)
    )
  end

  # `Airlock.Broker.box_env/1` builds the proxy URL from the address the
  # listener bound to. Once the box is elsewhere, the box's address for the
  # broker is the tunnel's, and only the host part changes.
  defp proxy_env(%Broker{} = broker, broker_host) do
    url = "http://#{broker.token}:#{broker.label}@#{broker_host}"

    %{
      "HTTP_PROXY" => url,
      "HTTPS_PROXY" => url,
      "http_proxy" => url,
      "https_proxy" => url
    }
  end

  # Checked before anything is created, for the same reason reachability
  # is: `Managoat.Sandbox.Sprites.Client.get!/0` *raises* on a missing
  # token, from inside the library, several frames down — and by then a
  # broker session has been minted and a telemetry handler attached.
  defp provider_ready(provider) do
    case provider_credential(provider) do
      :none -> :ok
      {_key, value} when is_binary(value) and value != "" -> :ok
      {key, _} -> {:error, {:provider_not_configured, provider, key}}
    end
  end

  defp provider_credential(:sprites),
    do: {"SPRITES_TOKEN", Sandbox.Config.get(Managoat.Sandbox.Sprites, :token)}

  defp provider_credential(:e2b),
    do: {"E2B_API_KEY", Sandbox.Config.get(Managoat.Sandbox.E2B, :api_key)}

  defp provider_credential(:daytona),
    do: {"DAYTONA_API_KEY", Sandbox.Config.get(Managoat.Sandbox.Daytona, :api_key)}

  # The runner authenticates a daemon at the endpoint, not a provider API,
  # and the fakes authenticate nothing.
  defp provider_credential(_provider), do: :none

  # The environment wins: an explicitly exported value is a deliberate one,
  # and a found credential is a convenience.
  defp default_vars, do: Map.merge(Credentials.inference_credentials(), System.get_env())

  defp known_runtime(runtime) do
    if runtime in Runtime.supported() do
      :ok
    else
      {:error, {:unknown_runtime, runtime, Runtime.supported()}}
    end
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
end
