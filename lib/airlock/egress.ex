defmodule Airlock.Egress do
  @moduledoc """
  The egress log: a `:telemetry` handler on `[:managoat, :broker, :request]`
  and the rows it collects.

  One row per request the proxy decided about — method, host, path, the
  verdict, and the rule that decided it. This is the **Egress** tab of the
  record and it is the evidence the product is sold on.

  `PLAN.md` puts printing it at M0 step 8. The handler is here at step 3
  because it is how a broker with no box attached can be shown to work at
  all, and because it is the piece `CLAUDE.md` warns hardest about.

  ## Why every callback is wrapped in `try`

  **A raising `:telemetry` handler is detached, not retried.** It fails
  nothing and reports nothing; it stops running. Airlock's entire record is
  a telemetry handler, so a bug in it looks exactly like an agent that made
  no requests — the most expensive way for this program to be wrong, since
  the failure mode is a clean-looking egress log rather than an error.

  So `handle_event/4` rescues everything, and a row it could not make sense
  of is recorded as `:malformed` rather than dropped: a row that says "the
  proxy decided something and this handler could not read it" is evidence,
  and a missing row is not. `egress_test.exs` feeds it metadata with the
  wrong shape and then asserts the handler is **still attached**, because a
  guard that has stopped guarding looks exactly like one that finds nothing.

  ## Why rows are filtered by the run

  Telemetry handlers are global: an `async: true` test that attaches one
  sees events from every other test running concurrently, and so would a
  bakeoff running four runtimes at once (M4).

  `Managoat.Broker.Session`'s `meta` travels unchanged into every event for
  a request served under that session, so `Airlock.Broker` mints each run's
  session with `meta: %{run: run_id}` and this handler keeps only the rows
  whose `meta.run` matches. That is what `meta` is for, it needs no
  coordination, and it makes the record's rows provably one run's.

  ## The verdict is `scheme`, not `outcome`

  `outcome` answers "did a rule apply", and a matched `:passthrough` rule —
  the documented way a host is allowed under `deny` — is a rule applying.
  So it reports `outcome: :injected` exactly as a `:bearer` rule does, and
  `outcome: :passthrough` means the opposite: that *no* rule matched, which
  cannot happen under `unmatched_host_policy: :deny` at all.

  Taken at face value that makes the README's own table wrong — every
  allowed host would read `injected`, and "which requests actually carried
  one of my credentials", the question the record exists to answer, would
  have no answer in it.

  The event now carries **`scheme`**: the scheme of the rule `rule` names.
  That is what a verdict is read from:

  | | verdict |
  |---|---|
  | `scheme: :passthrough` | `:passthrough` — reached untouched |
  | any other scheme | `:injected` — a credential was attached |
  | no rule, let through | `:passthrough` |
  | refused | `:denied` |

  Airlock compiles its own rules, so until `managoat_broker` 0.11.0 it
  could reconstruct this from the rule's *name*. It was a workaround, and
  the issue that reported it (managoat_broker#27, filed from building this
  module) closed by adding the field — so the workaround is gone rather
  than kept beside the real answer. A consumer whose rules come from
  somewhere else never had the option.

  ## What a row cannot contain

  No header and no body — the library never puts them in the event — and
  `path` is the URL path only, never the query string, because a query can
  carry a credential the proxy never saw and therefore never brokered. That
  is the library's choice and this module does not undo it.
  """

  use Agent

  @typedoc """
  One decided request. `rule` names the rule that actually set the header,
  falling back to the first matched rule when none did — broker 0.7.0's
  contract — or is `nil` when nothing matched. `scheme` is that rule's, and
  `verdict` is read from it; see the moduledoc.
  """
  @type row :: %{
          method: String.t() | nil,
          host: String.t() | nil,
          path: String.t() | nil,
          verdict: :injected | :passthrough | :denied | :malformed,
          rule: String.t() | nil,
          scheme: atom() | nil,
          status: non_neg_integer() | nil,
          error: atom() | nil,
          duration_ms: float() | nil
        }

  @event [:managoat, :broker, :request]

  @doc """
  Start a collector for `run` and attach the handler.

  `run` is the id `Airlock.Broker` minted the session's `meta` with; only
  that run's rows are kept. Returns the collector's pid.
  """
  @spec start_link(keyword()) :: {:ok, pid()} | {:error, term()}
  def start_link(opts) do
    run = Keyword.fetch!(opts, :run)
    name = Keyword.get(opts, :name, name_for(run))

    with {:ok, pid} <- Agent.start_link(fn -> [] end, name: name),
         :ok <-
           :telemetry.attach(handler_id(run), @event, &__MODULE__.handle_event/4, %{
             run: run,
             collector: name
           }) do
      {:ok, pid}
    end
  end

  @doc "A child spec, so a run's egress log can sit in a supervision tree."
  @spec child_spec(keyword()) :: Supervisor.child_spec()
  def child_spec(opts) do
    %{id: {__MODULE__, Keyword.fetch!(opts, :run)}, start: {__MODULE__, :start_link, [opts]}}
  end

  @doc "Detach the handler for `run`. The collector stays, so its rows survive."
  @spec detach(String.t()) :: :ok | {:error, :not_found}
  def detach(run), do: :telemetry.detach(handler_id(run))

  @doc """
  Is the handler for `run` still attached?

  Worth asserting rather than assuming: a telemetry handler that raised is
  gone, and nothing says so.
  """
  @spec attached?(String.t()) :: boolean()
  def attached?(run) do
    @event |> :telemetry.list_handlers() |> Enum.any?(&(&1.id == handler_id(run)))
  end

  @doc "The rows collected for `run`, oldest first."
  @spec rows(String.t()) :: [row()]
  def rows(run), do: run |> name_for() |> Agent.get(&Enum.reverse(&1))

  @doc "The handler's telemetry id for `run`."
  @spec handler_id(String.t()) :: {module(), String.t()}
  def handler_id(run), do: {__MODULE__, run}

  @doc false
  # Public because `:telemetry.attach/4` needs a remote call: a local
  # function capture in a handler holds a reference to this module's
  # current version and stops the handler surviving a recompile.
  @spec handle_event(list(), map(), map(), map()) :: :ok
  # `run` and `collector` are matched in the head rather than destructured
  # in the body, so the `rescue` below can still name the collector when
  # the body is what failed.
  def handle_event(@event, measurements, metadata, %{run: run, collector: collector}) do
    if this_run?(metadata, run) do
      Agent.update(collector, &[row(measurements, metadata) | &1])
    end

    :ok
  rescue
    # See the moduledoc: a raise here detaches the handler for the rest of
    # the run, and the log then looks like an agent that made no requests.
    exception ->
      safe_record(collector, exception)
      :ok
  catch
    kind, reason ->
      safe_record(collector, {kind, reason})
      :ok
  end

  # ── rows ───────────────────────────────────────────────────────────────────

  defp this_run?(metadata, run) do
    case metadata do
      %{meta: %{run: ^run}} -> true
      _ -> false
    end
  end

  defp row(measurements, metadata) do
    %{
      method: metadata[:method],
      host: metadata[:host],
      path: metadata[:path],
      verdict: verdict(metadata[:outcome], metadata[:scheme]),
      rule: metadata[:rule],
      scheme: metadata[:scheme],
      status: metadata[:status],
      error: metadata[:error],
      duration_ms: duration_ms(measurements[:duration])
    }
  end

  # See the moduledoc: `outcome` says a rule applied, `scheme` says what it
  # did, and only the second answers "was a credential attached".
  defp verdict(:denied, _scheme), do: :denied

  # A `:passthrough` rule matched and attached nothing; or no rule matched
  # and the session let it through anyway, which is `scheme: nil` and only
  # possible under `unmatched: passthrough`. Both reached the origin
  # untouched, which is what the row says.
  defp verdict(outcome, scheme)
       when outcome in [:injected, :passthrough] and
              scheme in [:passthrough, nil],
       do: :passthrough

  defp verdict(outcome, scheme) when outcome in [:injected, :passthrough] and is_atom(scheme),
    do: :injected

  # A version of the library this code has not read. Recorded as such
  # rather than guessed at or dropped.
  defp verdict(_outcome, _scheme), do: :malformed

  # `duration` is monotonic native units; the event's own moduledoc says a
  # host converts it to whatever it stores.
  defp duration_ms(nil), do: nil

  defp duration_ms(duration) when is_integer(duration) do
    System.convert_time_unit(duration, :native, :microsecond) / 1000
  end

  defp duration_ms(_other), do: nil

  defp safe_record(collector, reason) do
    Agent.update(collector, &[malformed(reason) | &1])
  rescue
    _ -> :ok
  catch
    _, _ -> :ok
  end

  defp malformed(reason) do
    %{
      method: nil,
      host: nil,
      path: nil,
      verdict: :malformed,
      rule: nil,
      scheme: nil,
      status: nil,
      error: error_atom(reason),
      duration_ms: nil
    }
  end

  defp error_atom(%{__struct__: module}), do: module
  defp error_atom(_other), do: :handler_error

  defp name_for(run),
    do: Module.concat(__MODULE__, "Run_" <> Base.url_encode64(run, padding: false))
end
