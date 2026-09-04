defmodule Airlock.TranscriptTest do
  @moduledoc """
  The accumulator the record is drawn from.

  Two things here are not obvious from the shape and both were bugs first:
  a run of `:text` blocks is one message and the next run is another, and
  a block carries the time it arrived because nothing in the protocol does.
  """

  use ExUnit.Case, async: true

  alias Airlock.Transcript

  describe "messages/1" do
    test "adjacent chunks are one message" do
      transcript = Transcript.new() |> text("the ") |> text("answer")

      assert Transcript.messages(transcript) == ["the answer"]
      assert Transcript.text(transcript) == "the answer"
    end

    test "a tool call between two runs of text ends the first message" do
      # M0's records read "...I have fetched it now.You denied the second
      # request..." because every `:text` block in the turn was joined with
      # nothing. Adjacency is what makes them one message, not kind.
      transcript =
        Transcript.new()
        |> text("I have fetched it now.")
        |> tool_call("t1", "WebFetch")
        |> tool_result("t1", "completed")
        |> text("You denied the second request.")

      assert Transcript.messages(transcript) == [
               "I have fetched it now.",
               "You denied the second request."
             ]

      assert Transcript.text(transcript) ==
               "I have fetched it now.\n\nYou denied the second request."
    end

    test "a thought ends a message too, and is not one" do
      transcript = Transcript.new() |> text("before") |> thinking("hmm") |> text("after")

      assert Transcript.messages(transcript) == ["before", "after"]
    end

    test "the text is under :body, and an empty transcript says nothing" do
      # Reading `:text` gets nil on every block and concatenates to "",
      # which looks exactly like an agent that said nothing — so this
      # asserts on content rather than on shape.
      assert Transcript.text(Transcript.new()) == ""

      assert [%{kind: :text, body: "hi"}] =
               Transcript.of_kind(text(Transcript.new(), "hi"), :text)
    end
  end

  describe "tool_calls/1" do
    test "threads a call to its result and times it" do
      transcript =
        Transcript.new()
        |> tool_call("t1", "Read(mix.exs)")
        |> tool_result("t1", "completed", "defmodule …")

      assert [call] = Transcript.tool_calls(transcript)
      assert call.name == "Read(mix.exs)"
      assert call.status == :ok
      assert call.output =~ "defmodule"
      assert is_integer(call.at_ms) and call.at_ms >= 0
      assert is_integer(call.duration_ms) and call.duration_ms >= 0
    end

    test "a failed result is failed, and a missing one is open" do
      transcript =
        Transcript.new()
        |> tool_call("t1", "a")
        |> tool_result("t1", "failed")
        |> tool_call("t2", "b")

      assert [%{status: :failed}, %{status: :open, duration_ms: nil}] =
               Transcript.tool_calls(transcript)
    end

    test "a result whose call is not in this transcript is dropped, not orphaned" do
      # What reattach (M1) will look like: the call was announced before
      # this transcript existed.
      transcript = Transcript.new() |> tool_result("gone", "completed")

      assert Transcript.tool_calls(transcript) == []
    end

    test "stamps every block with when it arrived" do
      # A `session/update` carries no time of its own, so the process that
      # read it is the only place the information exists.
      transcript = Transcript.new()
      Process.sleep(15)
      transcript = text(transcript, "late")

      assert [%{at_ms: at_ms}] = transcript.blocks
      assert at_ms >= 10
    end
  end

  describe "add_stderr/3" do
    test "keeps the tail, because the adapter has usually already said why" do
      transcript = Transcript.add_stderr(Transcript.new(), String.duplicate("x", 50) <> "END", 10)

      assert transcript.stderr == "xxxxxxxEND"
    end
  end

  # ── helpers ────────────────────────────────────────────────────────────────

  defp text(transcript, body) do
    add(transcript, %{
      "sessionUpdate" => "agent_message_chunk",
      "content" => %{"type" => "text", "text" => body}
    })
  end

  defp thinking(transcript, body) do
    add(transcript, %{
      "sessionUpdate" => "agent_thought_chunk",
      "content" => %{"type" => "text", "text" => body}
    })
  end

  defp tool_call(transcript, id, title) do
    add(transcript, %{"sessionUpdate" => "tool_call", "toolCallId" => id, "title" => title})
  end

  defp tool_result(transcript, id, status, output \\ "") do
    add(transcript, %{
      "sessionUpdate" => "tool_call_update",
      "toolCallId" => id,
      "status" => status,
      "content" => [
        %{"type" => "content", "content" => %{"type" => "text", "text" => output}}
      ]
    })
  end

  defp add(transcript, update) do
    line =
      Jason.encode!(%{
        "jsonrpc" => "2.0",
        "method" => "session/update",
        "params" => %{"sessionId" => "s1", "update" => update}
      })

    Transcript.add_line(transcript, line)
  end
end
