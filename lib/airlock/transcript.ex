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
  """

  alias Managoat.ACP.Blocks

  @type t :: %__MODULE__{
          blocks: [map()],
          session_id: String.t() | nil,
          stop_reason: String.t() | nil,
          usage: map() | nil,
          stderr: String.t()
        }

  defstruct blocks: [], session_id: nil, stop_reason: nil, usage: nil, stderr: ""

  @doc "An empty transcript."
  @spec new() :: t()
  def new, do: %__MODULE__{}

  @doc """
  Add the blocks one line of agent output parses into.

  A line that parses into nothing — a `plan` update, a `user_message_chunk`
  we already rendered as the prompt — adds nothing, which is
  `Managoat.ACP.Blocks`' decision and not one to second-guess here.
  """
  @spec add_line(t(), String.t()) :: t()
  def add_line(%__MODULE__{} = transcript, line) do
    case Blocks.from_line(line) do
      [] -> transcript
      blocks -> %{transcript | blocks: transcript.blocks ++ blocks}
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

  @doc "The blocks of one kind, in order."
  @spec of_kind(t(), atom()) :: [map()]
  def of_kind(%__MODULE__{blocks: blocks}, kind),
    do: Enum.filter(blocks, &(Map.get(&1, :kind) == kind))

  @doc """
  The agent's assistant text, concatenated — adjacent chunks are one
  message, which is what `Managoat.ACP.Blocks` says a renderer does.

  The text lives under `:body`, not `:text`: `:kind` names what the block
  is and `:body` carries it, for every block shape. Reading `:text` gets
  `nil` on every block and concatenates to `""`, which looks exactly like
  an agent that said nothing.
  """
  @spec text(t()) :: String.t()
  def text(%__MODULE__{} = transcript) do
    transcript
    |> of_kind(:text)
    |> Enum.map_join("", &(Map.get(&1, :body) || ""))
  end
end
