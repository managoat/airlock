defmodule Airlock.ChangesTest do
  @moduledoc """
  M2 step 3: what the agent left behind.

  These run the scripts against the git on this machine, through
  `Airlock.Test.LocalBox`, because the scripts are the half that can be
  wrong in ways a fake cannot show — a pathspec that excludes nothing, a
  `-z` record shape that is not what git emits, a pipeline whose exit
  status is `base64`'s. All of those pass against a box that answers every
  command with exit 0.

  The parsers are exercised through the same path rather than with canned
  strings, so what is asserted is git's output and not a memory of it.
  """

  use ExUnit.Case, async: true

  alias Airlock.Box
  alias Airlock.Changes
  alias Airlock.Test.LocalBox
  alias Managoat.Sandbox.Handle

  setup do
    dir = Path.join(System.tmp_dir!(), "airlock-changes-#{System.unique_integer([:positive])}")
    File.mkdir_p!(dir)
    on_exit(fn -> File.rm_rf(dir) end)

    box = %Box{
      handle: %Handle{provider: :local_box, name: "local"},
      provider: :local_box,
      name: "local"
    }

    adapters = Managoat.Sandbox.adapters()
    Application.put_env(:managoat_sandbox, :adapters, Map.put(adapters, :local_box, LocalBox))
    on_exit(fn -> Application.put_env(:managoat_sandbox, :adapters, adapters) end)

    %{dir: dir, box: box}
  end

  describe "baseline/3" do
    test "makes a repository where there was none, and returns its commit", %{dir: dir, box: box} do
      File.write!(Path.join(dir, "from-provisioning.txt"), "written before the turn\n")

      assert {:ok, %{cwd: ^dir, ref: ref}} = Changes.baseline(box, dir)
      assert String.match?(ref, ~r/\A[0-9a-f]{40}\z/)
      assert File.dir?(Path.join(dir, ".git"))
    end

    test "an empty workspace still has a starting state", %{dir: dir, box: box} do
      # `--allow-empty`. A baseline that refused an empty workspace would
      # take the tab away from exactly the runs that changed nothing.
      assert {:ok, %{ref: ref}} = Changes.baseline(box, dir)
      assert byte_size(ref) == 40
    end

    test "a workspace that does not exist is named, not guessed at", %{box: box} do
      assert {:error, :workspace_missing} = Changes.baseline(box, "/no/such/workspace")
    end
  end

  describe "since/3" do
    test "a new file is in the diff, which a plain `git diff` would miss", %{dir: dir, box: box} do
      # The whole reason for the baseline. An agent's output is mostly new
      # files, and `git diff` on a working tree shows none of them.
      {:ok, baseline} = Changes.baseline(box, dir)
      File.write!(Path.join(dir, "answer.txt"), "42\n")

      assert {:ok, changes} = Changes.since(box, baseline)
      assert [%{path: "answer.txt", status: "added", added: 1, removed: 0}] = changes.files
      assert changes.diff =~ "+42"
      refute changes.truncated
    end

    test "counts a modification and a deletion, and names each", %{dir: dir, box: box} do
      File.write!(Path.join(dir, "keep.txt"), "one\ntwo\n")
      File.write!(Path.join(dir, "gone.txt"), "bye\n")
      {:ok, baseline} = Changes.baseline(box, dir)

      File.write!(Path.join(dir, "keep.txt"), "one\ntwo\nthree\n")
      File.rm!(Path.join(dir, "gone.txt"))

      assert {:ok, changes} = Changes.since(box, baseline)
      by_path = Map.new(changes.files, &{&1.path, &1})

      assert %{status: "modified", added: 1, removed: 0} = by_path["keep.txt"]
      assert %{status: "deleted", added: 0, removed: 1} = by_path["gone.txt"]
    end

    test "a turn that changed nothing says so with an empty list, not an error", %{
      dir: dir,
      box: box
    } do
      {:ok, baseline} = Changes.baseline(box, dir)

      assert {:ok, %{files: [], diff: ""}} = Changes.since(box, baseline)
    end

    test "the excluded paths are excluded, and the list travels with the diff", %{
      dir: dir,
      box: box
    } do
      # A workspace is a home directory for claude and codex, so it holds
      # the harness's own bookkeeping — and every bit of that changes on
      # every turn whatever the prompt was.
      {:ok, baseline} = Changes.baseline(box, dir)

      File.mkdir_p!(Path.join(dir, "node_modules/left-pad"))
      File.write!(Path.join(dir, "node_modules/left-pad/index.js"), "noise\n")
      File.mkdir_p!(Path.join(dir, ".claude/projects"))
      File.write!(Path.join(dir, ".claude/projects/session.jsonl"), "noise\n")
      File.mkdir_p!(Path.join(dir, "src/node_modules"))
      File.write!(Path.join(dir, "src/node_modules/nested.js"), "noise\n")

      # Files, not directories. The first real run against Sprites got both
      # of these into the record — `.claude.json` is 950 lines of feature
      # flags the harness caches on startup — because every pathspec was
      # `**/X/**`, which silently matches nothing when `X` is a file.
      File.write!(Path.join(dir, ".claude.json"), "{\"flags\": true}\n")
      File.write!(Path.join(dir, ".zcompdump-box-5.9"), "noise\n")

      File.write!(Path.join(dir, "src/real.js"), "work\n")

      assert {:ok, changes} = Changes.since(box, baseline)

      assert Enum.map(changes.files, & &1.path) == ["src/real.js"]
      assert "node_modules" in changes.excluded
      assert ".claude" in changes.excluded
    end

    test "a binary file has no line counts, which is not the same as zero", %{
      dir: dir,
      box: box
    } do
      {:ok, baseline} = Changes.baseline(box, dir)
      File.write!(Path.join(dir, "blob.bin"), <<0, 1, 2, 0, 255>>)

      assert {:ok, %{files: [%{path: "blob.bin", added: nil, removed: nil}]}} =
               Changes.since(box, baseline)
    end

    test "the patch is capped and says it was, and the file list still is not", %{
      dir: dir,
      box: box
    } do
      {:ok, baseline} = Changes.baseline(box, dir)
      File.write!(Path.join(dir, "big.txt"), String.duplicate("a line of text\n", 500))
      File.write!(Path.join(dir, "small.txt"), "x\n")

      assert {:ok, changes} = Changes.since(box, baseline, max_bytes: 200)
      assert changes.truncated
      assert byte_size(changes.diff) <= 200

      # A truncated patch with a complete list of what it truncated is
      # still evidence; a truncated list is not.
      assert length(changes.files) == 2
    end

    test "redacts what it is told to, and nothing else", %{dir: dir, box: box} do
      # The box holds placeholders, not credentials. The one secret on it
      # is the broker's session token, which rides in the proxy URL.
      {:ok, baseline} = Changes.baseline(box, dir)

      File.write!(
        Path.join(dir, "leaked.env"),
        "HTTPS_PROXY=http://sk-broker-token-abcdef123456:airlock@host:1\n" <>
          "ANTHROPIC_API_KEY=PLACEHOLDER-AIRLOCK-ANTHROPIC\n"
      )

      assert {:ok, changes} =
               Changes.since(box, baseline, redact: ["sk-broker-token-abcdef123456"])

      refute changes.diff =~ "sk-broker-token"
      assert changes.diff =~ "[REDACTED]"

      # A placeholder in the diff is evidence the containment worked, so it
      # stays.
      assert changes.diff =~ "PLACEHOLDER-AIRLOCK-ANTHROPIC"
    end

    test "a workspace with no repository is named rather than reported as no changes", %{
      dir: dir,
      box: box
    } do
      assert {:error, :not_a_repository} =
               Changes.since(box, %{cwd: dir, ref: "0000000000000000000000000000000000000000"})
    end
  end

  describe "the exec boundary" do
    test "maps each reserved exit code to something a reader can act on" do
      assert {:error, :git_unavailable} = Changes.from_baseline_exec({:ok, "", 8}, "/w")
      assert {:error, :workspace_missing} = Changes.from_baseline_exec({:ok, "", 5}, "/w")
      assert {:error, :not_a_repository} = Changes.from_diff_exec({:ok, "", 6}, "/w", 10, [])
      assert {:error, {:git_failed, "boom"}} = Changes.from_baseline_exec({:ok, "boom", 9}, "/w")
      assert {:error, {:box, :timeout}} = Changes.from_baseline_exec({:error, :timeout}, "/w")
    end

    test "a box that answers everything with exit 0 is unreadable, not empty" do
      # `Airlock.Test.FakeBox` is exactly this, and so is any adapter that
      # stubs `exec`. An empty diff and an unanswered one must not look the
      # same: one says the agent changed nothing.
      assert {:error, {:unreadable, _}} = Changes.from_baseline_exec({:ok, "", 0}, "/w")
      assert {:error, {:unreadable, _}} = Changes.from_diff_exec({:ok, "", 0}, "/w", 10, [])
    end
  end
end
