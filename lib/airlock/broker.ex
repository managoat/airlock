defmodule Airlock.Broker do
  @moduledoc """
  The proxy that is the box's only way out, and the session a run is served
  under.

  `Managoat.Broker` is the listener; this module is what `CLAUDE.md` calls
  the broker wiring: start it beside the app, mint a session per run from a
  policy, and hand the box its proxy address and its placeholders.

  ## One run, one session, one CA

  The session's token is minted per run and the CA seed is 32 random bytes
  per run. Both follow from `PLAN.md`'s settled question 4 — a box is
  per-job and destroyed after it — so nothing outlives the run that would
  need a stable seed, and a leaked token or a lifted root certificate is
  worth nothing after the box it was for is gone.

  A deployment with several replicas behind one address needs the same seed
  on every one of them, which is a real constraint and not this one: with
  the box and the broker on the same machine there is one replica.

  ## What the box is told

  `box_env/1` is the environment a runtime is provisioned with:

    * `HTTPS_PROXY`, `HTTP_PROXY` and their lowercase twins, as
      `http://<token>:<label>@<host>:<port>`. The `label` half is there
      because some clients — git — refuse a proxy URL with a user and no
      password; `Managoat.Broker.Store` says the token alone is the
      binding, so the label is cosmetic and carries no secret;
    * `NO_PROXY` for loopback, so a runtime talking to something on its own
      box does not send it through the proxy;
    * the placeholders, from `Airlock.Policy.Compile.placeholders/1`.

  The root certificate the box has to trust is `ca_pem/1`. Installing it is
  provisioning's job (step 5), not this module's.

  ## Traps this module cannot fix for you

  `CLAUDE.md` records both, and neither is solvable here:

    * **`sudo` strips the proxy environment** unless sudoers `env_keep` is
      set. An agent that runs anything under `sudo` egresses unbrokered —
      except that under `Airlock.Policy.Compile`'s answer the box's only
      allowed destination *is* the broker, so it egresses nowhere instead.
      That is the loud failure the compiler's moduledoc argues for;
    * **npm 9 sends no proxy credentials at all**, so its requests reach
      the proxy without a `Proxy-Authorization` header and are refused with
      `407`. This is why `PLAN.md` orders npm before the seal.
  """

  alias Airlock.Policy
  alias Airlock.Policy.Compile
  alias Managoat.Broker
  alias Managoat.Broker.Session
  alias Managoat.Broker.Store

  @typedoc """
  A minted run: the listener's name and port, the session token, and the
  seed the root certificate is derived from. Never the credentials — those
  are inside the session, in the store, which is the only place they exist.
  """
  @type t :: %__MODULE__{
          name: atom(),
          store: {module(), atom()},
          token: String.t(),
          label: String.t(),
          ca_seed: binary(),
          host: String.t(),
          port: :inet.port_number(),
          run: String.t(),
          placeholders: %{optional(String.t()) => String.t()},
          schemes: %{optional(String.t()) => Managoat.Broker.Rule.scheme()}
        }

  @enforce_keys [
    :name,
    :store,
    :token,
    :label,
    :ca_seed,
    :host,
    :port,
    :run,
    :placeholders,
    :schemes
  ]
  defstruct [
    :name,
    :store,
    :token,
    :label,
    :ca_seed,
    :host,
    :port,
    :run,
    :placeholders,
    :schemes
  ]

  @doc """
  Start a broker for one run and mint its session.

  Options:

    * `:policy` — required, an `Airlock.Policy`;
    * `:vars` — the variable map credential references resolve against.
      Defaults to `System.get_env/0`, which is where a policy's
      `from: env:NAME` means;
    * `:port` — the listener port. Defaults to `0`, an ephemeral one, which
      is what a per-job broker on the user's own machine wants;
    * `:host` — the host the box addresses the broker by. Defaults to
      `"127.0.0.1"`, which is the local-box case;
    * `:supervisor` — a `Supervisor` to start the listener and store under.
      Defaults to starting them linked to the caller;
    * `:allow_private_upstreams` — passed through, default `false`. See
      `Airlock.Policy.Compile` for why the local box does not need it true;
    * `:name` — the listener's name, so more than one can run in a test;
    * `:run` — the run id stamped into the session's `meta`, which is how
      `Airlock.Egress` tells this run's rows from another's on a global
      telemetry handler. Defaults to a random one.

  Returns `{:error, {:missing_vars, names}}` naming **every** variable the
  policy needs and `vars` does not hold, rather than the first.
  """
  @spec start_link(keyword()) :: {:ok, t()} | {:error, term()}
  def start_link(opts) do
    policy = Keyword.fetch!(opts, :policy)
    vars = Keyword.get_lazy(opts, :vars, &System.get_env/0)
    name = Keyword.get(opts, :name, Airlock.Broker.Listener)
    store_name = Module.concat(name, Store)

    with {:ok, rules} <- Compile.rules(policy, vars) do
      ca_seed = :crypto.strong_rand_bytes(32)
      token = Store.Memory.generate_token()
      run = Keyword.get_lazy(opts, :run, &generate_run_id/0)

      children = [
        {Store.Memory, name: store_name},
        {Broker,
         name: name,
         port: Keyword.get(opts, :port, 0),
         store: {Store.Memory, store_name},
         ca_seed: ca_seed,
         allow_private_upstreams: Keyword.get(opts, :allow_private_upstreams, false),
         upstream_ssl_options: Keyword.get(opts, :upstream_ssl_options, [])}
      ]

      with :ok <- start_children(children, Keyword.get(opts, :supervisor)) do
        :ok = Store.Memory.put(store_name, token, build_session(policy, rules, run))

        {:ok,
         %__MODULE__{
           name: name,
           store: {Store.Memory, store_name},
           token: token,
           label: "airlock",
           ca_seed: ca_seed,
           host: Keyword.get(opts, :host, "127.0.0.1"),
           port: Broker.port(name),
           run: run,
           placeholders: Compile.placeholders(policy),
           schemes: Compile.rule_schemes(policy)
         }}
      end
    end
  end

  @doc "The proxy URL the box is given: credentials, host and port."
  @spec proxy_url(t()) :: String.t()
  def proxy_url(%__MODULE__{} = broker) do
    "http://#{broker.token}:#{broker.label}@#{broker.host}:#{broker.port}"
  end

  @doc """
  The environment a box is provisioned with: the proxy, `NO_PROXY`, and the
  placeholders. See the moduledoc.
  """
  @spec box_env(t()) :: %{optional(String.t()) => String.t()}
  def box_env(%__MODULE__{} = broker) do
    url = proxy_url(broker)

    %{
      "HTTP_PROXY" => url,
      "HTTPS_PROXY" => url,
      "http_proxy" => url,
      "https_proxy" => url,
      "NO_PROXY" => "localhost,127.0.0.1,::1",
      "no_proxy" => "localhost,127.0.0.1,::1"
    }
    |> Map.merge(broker.placeholders)
  end

  @doc "The root certificate the box must trust, as PEM."
  @spec ca_pem(t()) :: String.t()
  def ca_pem(%__MODULE__{ca_seed: seed}), do: Broker.ca_pem_for_seed(seed)

  @doc "The session this run is served under, as the store holds it."
  @spec session(t()) :: {:ok, Session.t()} | :error
  def session(%__MODULE__{store: store, token: token}), do: Store.lookup(store, token)

  @doc "Is the listener up?"
  @spec running?(t()) :: boolean()
  def running?(%__MODULE__{name: name}), do: Broker.running?(name)

  # ── minting ────────────────────────────────────────────────────────────────

  # `meta` travels unchanged into every request event served under this
  # session, so stamping the run there is what lets a global telemetry
  # handler keep one run's rows apart from another's. See `Airlock.Egress`.
  defp build_session(%Policy{} = policy, rules, run) do
    %Session{
      rules: rules,
      unmatched_host_policy: policy.unmatched,
      expires_at: expires_at(policy.expires_in),
      meta: %{run: run}
    }
  end

  defp generate_run_id, do: 8 |> :crypto.strong_rand_bytes() |> Base.encode16(case: :lower)

  defp expires_at(nil), do: nil
  defp expires_at(seconds), do: DateTime.add(DateTime.utc_now(), seconds, :second)

  # Linked to the caller when no supervisor is named: one run, one broker,
  # and the run's process is the thing whose life it should share. The
  # store must be up before the listener, which a `:one_for_one` in this
  # order gives.
  defp start_children(children, nil) do
    case Supervisor.start_link(children, strategy: :one_for_one) do
      {:ok, _pid} -> :ok
      {:error, reason} -> {:error, reason}
    end
  end

  defp start_children(children, supervisor) do
    Enum.reduce_while(children, :ok, fn child, :ok ->
      case Supervisor.start_child(supervisor, child) do
        {:ok, _pid} -> {:cont, :ok}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
  end
end
