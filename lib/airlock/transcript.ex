defmodule Airlock.Transcript do
  @moduledoc """
  What the agent said and did, as `Managoat.ACP.Blocks` blocks.

  M0 step 8's other half — the egress log is `Airlock.Egress`. Kept apart
  from the driver for the same reason `Airlock.Render` is kept apart from
  `Airlock.CLI`: the record (M2) is a file with four tabs, and the thing
  the terminal and the file share is the block, not the drawing.

  ## Never a runtime dialect

  `PLAN.md`'s Transcript tab says "`Managoat.ACP.Blocks`, never a runtime
  dialect", and this is where that is enforced. Four proprietary output
  formats used to be parsed in Fountain's render path, where a vendor's
  point release becomes a rendering bug. Lines from the peer go through
  `Blocks.from_line/1` and nothing here looks at the runtime.

  ## What it holds

  Blocks in order, the agent's session id, the stop reason, and normalised
  token usage from `Managoat.ACP.Usage`. A plain struct — the run's
  durable state is the sandbox's (goatherd's finding 1), so this is an
  accumulator, not storage.

  ## Every block is stamped with when it arrived

  `Managoat.ACP.Blocks` carries no time, because a block is a translation
  of a message and a message does not know when it was read. The process
  that read it does, and that is the only place the information exists: an
  adapter's `session/update` has no timestamp in it.

  So `add_line/2` stamps each block with `at_ms`, milliseconds since
  `new/0`. That is what makes `tool_calls/1` able to say how long a tool
  call took, which is the whole of the record's Tools tab.

  ### Why not `Managoat.ACP.Tracer`

  `PLAN.md`'s Tools tab says "spans from `Managoat.ACP.Tracer`". Tracer
  emits **OpenTelemetry** spans, and its own moduledoc says "with no SDK
  started every span call is a no-op". Airlock depends on
  `opentelemetry_api` — through `managoat_acp`, transitively — and on no
  SDK, so wiring Tracer in would collect nothing at all and the Tools tab
  would be permanently, invisibly empty. Adding an SDK and an in-memory
  exporter to an escript to read back spans it just wrote is a long way
  round to data this module already holds in order.

  Tracer is not wrong and is not replaced: it is for a host with
  dashboards, and Airlock is a file. `NOTES-M2.md` has the finding.
  """

  alias Managoat.ACP.Blocks

  @type t :: %__MODULE__{
          blocks: [map()],
          session_id: String.t() | nil,
          stop_reason: String.t() | nil,
          usage: map() | nil,
          stderr: String.t(),
          started_at: integer()
        }

  @typedoc """
  One tool call, threaded to its result on `toolCallId` — which ACP does by
  construction, so this follows a thread rather than guessing at a pairing.

  `status` is `:open` when no terminal update ever arrived: the turn ended
  or the adapter died with the call in flight. That is a different thing
  from a failure and the record says so.
  """
  @type tool_call :: %{
          id: String.t() | nil,
          name: String.t(),
          summary: String.t(),
          input: String.t() | nil,
          output: String.t() | nil,
          status: :ok | :failed | :open,
          at_ms: non_neg_integer(),
          duration_ms: non_neg_integer() | nil
        }

  defstruct blocks: [],
            session_id: nil,
            stop_reason: nil,
            usage: nil,
            stderr: "",
            started_at: 0

  @doc "An empty transcript, and the clock every block's `at_ms` is against."
  @spec new() :: t()
  def new, do: %__MODULE__{started_at: System.monotonic_time(:millisecond)}

  @doc """
  Add the blocks one line of agent output parses into.

  A line that parses into nothing — a `plan` update, a `user_message_chunk`
  we already rendered as the prompt — adds nothing, which is
  `Managoat.ACP.Blocks`' decision and not one to second-guess here.
  """
  @spec add_line(t(), String.t()) :: t()
  def add_line(%__MODULE__{} = transcript, line) do
    case Blocks.from_line(line) do
      [] ->
        transcript

      blocks ->
        at_ms = System.monotonic_time(:millisecond) - transcript.started_at
        %{transcript | blocks: transcript.blocks ++ Enum.map(blocks, &Map.put(&1, :at_ms, at_ms))}
    end
  end

  @doc "Record the session id the agent opened, which is the durable identity."
  @spec put_session(t(), String.t()) :: t()
  def put_session(%__MODULE__{} = transcript, session_id),
    do: %{transcript | session_id: session_id}

  @doc "Record how the turn ended, and what it cost."
  @spec finish(t(), String.t(), map() | nil) :: t()
  def finish(%__MODULE__{} = transcript, stop_reason, usage),
    do: %{transcript | stop_reason: stop_reason, usage: usage}

  @doc """
  Keep the tail of the adapter's stderr.

  Never fed to the peer — it is not protocol — but kept, because when a
  turn fails the adapter has usually already said why there, and discarding
  it leaves only the protocol-level symptom. goatherd's finding, and it is
  worth carrying.
  """
  @spec add_stderr(t(), String.t(), pos_integer()) :: t()
  def add_stderr(%__MODULE__{} = transcript, data, limit \\ 4_000) do
    kept = transcript.stderr <> data
    %{transcript | stderr: String.slice(kept, -limit..-1//1)}
  end

  @doc """
  Every tool call the agent made, threaded to its result.

  The Tools tab, and the answer to "what did it actually do" that a
  transcript alone does not give: a turn's text says what the agent
  reported, and this says what it ran.

  A `:tool_result` with no `:tool_use` before it is dropped rather than
  shown as an orphan — it means the call arrived before this transcript
  started, which is what reattach (M1) will look like.
  """
  @spec tool_calls(t()) :: [tool_call()]
  def tool_calls(%__MODULE__{} = transcript) do
    results = transcript |> of_kind(:tool_result) |> Map.new(&{&1[:tool_id], &1})

    transcript
    |> of_kind(:tool_use)
    |> Enum.map(&pair(&1, Map.get(results, &1[:id])))
  end

  defp pair(use, result) do
    at_ms = Map.get(use, :at_ms, 0)

    %{
      id: use[:id],
      name: use[:name] || "tool",
      summary: use[:summary] || "",
      input: use[:body],
      output: result && result[:body],
      status: status(result),
      at_ms: at_ms,
      duration_ms: result && max(Map.get(result, :at_ms, at_ms) - at_ms, 0)
    }
  end

  # Not `:failed` — a call with no terminal update never reported an
  # outcome at all, and calling that a failure invents one.
  defp status(nil), do: :open
  defp status(%{error?: true}), do: :failed
  defp status(_result), do: :ok

  @doc "The blocks of one kind, in order."
  @spec of_kind(t(), atom()) :: [map()]
  def of_kind(%__MODULE__{blocks: blocks}, kind),
    do: Enum.filter(blocks, &(Map.get(&1, :kind) == kind))

  @doc """
  The agent's assistant text as messages: one string per run of adjacent
  `:text` blocks.

  **Adjacent** is the whole of it. `Managoat.ACP.Blocks` emits one block
  per `agent_message_chunk` and says a renderer concatenates adjacent ones,
  because a chunk is a fragment of a message and not a message. What it
  does not say is that *every* `:text` block in a turn is one message — a
  tool call between two of them ends the first and starts the second, and
  joining those with nothing runs two sentences together:

      ...I have fetched it now.You denied the second request...

  Which is what M0's records did. So a run of text blocks is a message, and
  anything else — a tool call, a result, a thought — ends it.

  The text lives under `:body`, not `:text`: `:kind` names what the block
  is and `:body` carries it, for every block shape. Reading `:text` gets
  `nil` on every block and concatenates to `""`, which looks exactly like
  an agent that said nothing.
  """
  @spec messages(t()) :: [String.t()]
  def messages(%__MODULE__{blocks: blocks}) do
    blocks
    |> Enum.chunk_by(&(Map.get(&1, :kind) == :text))
    |> Enum.filter(&match?([%{kind: :text} | _], &1))
    |> Enum.map(fn run -> Enum.map_join(run, "", &(Map.get(&1, :body) || "")) end)
    |> Enum.reject(&(&1 == ""))
  end

  @doc """
  The agent's assistant text, messages separated by a blank line.

  See `messages/1` for why the separator is not nothing.
  """
  @spec text(t()) :: String.t()
  def text(%__MODULE__{} = transcript), do: transcript |> messages() |> Enum.join("\n\n")
end
