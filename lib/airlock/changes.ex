defmodule Airlock.Changes do
  @moduledoc """
  What the agent left behind on the box: the record's **Changes** tab.

  M2's third piece, and the one with a prerequisite the others do not have
  — it has to read the box, and `Airlock.Run` destroys the box at the end
  of every run. So this is a *stage in the run*, bracketing the turn, not
  a step in the writer: `baseline/3` before the agent starts and `since/3`
  after it stops, both before `Airlock.Box.destroy/1`.

  ## Why a baseline, rather than `git diff`

  `PLAN.md` says this is where `Fountain.SandboxFiles` gets extracted into
  a library. It was read closely and it is the right shape — fixed scripts
  over `Managoat.Sandbox.exec/4`, positional parameters so a filename is
  never interpolated, base64 out so bytes survive whatever an adapter
  streams stdout over, and redaction on the way past. All of that is here.

  What did **not** transfer is its question. Fountain asks "what is
  uncommitted in this repository right now", because its sandboxes are
  long-lived and its conversations clone one. Airlock's box is per-job and
  starts with no repository at all (`PLAN.md`'s settled question 4), so
  `git diff` on it answers nothing — and the same settled question says
  what makes the per-job box worth its cost: *a run's diff is relative to a
  known starting state rather than to whatever the last run left behind.*

  So Airlock makes the starting state. `baseline/3` runs `git init` in the
  workspace if there is no repository, commits everything provisioning put
  there, and returns that commit. `since/3` stages the workspace again and
  diffs against it. The result is exactly the claim: everything that
  changed **because of this turn**, new files included — which a plain
  `git diff` misses, and new files are most of what an agent produces.

  ## Not extracted into a library, and why

  `CLAUDE.md` says to extract `Fountain.SandboxFiles` "when it is needed,
  not before", and being needed is not the whole test — a library wants a
  second consumer and a settled API. This has neither yet: it is one
  consumer, one operation of the three, and a baseline step Fountain does
  not want. Extracting now would freeze a shape before the only product
  with a policy has ever run it, which is the same reasoning that settled
  `provision.ex` in `PLAN.md`'s question 1.

  **Revisit when** a second consumer wants the pair — a known starting
  state and a diff against it. At that point the thing to extract is the
  bracket, and Airlock will have run it in anger.

  ## What is left out of the diff, and why that is said out loud

  A workspace is a home directory for claude and codex
  (`Managoat.Runtimes.ACP.cwd/1`), so it holds the agent harness's own
  bookkeeping — session logs, caches, npm's `_logs` — and every one of
  those changes on every turn whatever the prompt was. Left in, they bury
  the agent's actual work; taken out silently, the record claims a
  completeness it does not have.

  So `excludes/0` is a fixed list, it is passed to git as pathspecs, and
  `Airlock.Record` prints it in the tab. A reader can see what was not
  looked at.

  ## The one secret on the box

  The box holds placeholders, not credentials — that is the product — so
  there is very little to redact. There is one thing: the **proxy URL**
  carries the broker's session token, which is the authority to use every
  credential the policy names, and it is in the turn's environment. An
  agent that wrote its environment to a file would put it in the diff.
  `since/3` takes `:redact` and `Airlock.Run` passes the token.

  Placeholders are deliberately *not* redacted. A placeholder in the diff
  is evidence the containment worked.
  """

  alias Airlock.Box

  @type baseline :: %{cwd: String.t(), ref: String.t()}

  @typedoc "One changed file. `added`/`removed` are `nil` for a binary file."
  @type file :: %{
          path: String.t(),
          status: String.t(),
          added: non_neg_integer() | nil,
          removed: non_neg_integer() | nil
        }

  @type t :: %{
          cwd: String.t(),
          files: [file()],
          diff: String.t(),
          truncated: boolean(),
          excluded: [String.t()]
        }

  @type error ::
          :git_unavailable
          | :workspace_missing
          | :not_a_repository
          | {:git_failed, String.t()}
          | {:unreadable, String.t()}
          | {:box, term()}

  # Exit codes the scripts reserve. Anything else nonzero is git itself
  # failing, surfaced with its output.
  @exit_workspace_missing 5
  @exit_not_repository 6
  @exit_no_git 8
  @exit_git_failed 9

  @default_max_bytes 262_144
  @timeout 120_000

  # Everything git needs to make a commit with no identity configured, and
  # nothing that would touch the box's own git config.
  @git_identity ~w(-c user.email=airlock@invalid -c user.name=airlock -c commit.gpgsign=false)

  # The agent harness's own bookkeeping and the usual build output. See the
  # moduledoc: these change on every turn whatever the prompt was, and the
  # tab says which ones were skipped rather than implying completeness.
  @excludes ~w(
    .git .ssh .cache .npm .bun .local .config .airlock
    .claude .codex .gemini .opencode
    node_modules __pycache__ .venv venv .tox
    target dist build .next .nuxt
  )

  @doc """
  The paths left out of the diff. Rendered in the record, so a reader can
  see what was not looked at.
  """
  @spec excludes() :: [String.t()]
  def excludes, do: @excludes

  @doc "The diff's byte cap when the caller names none."
  @spec default_max_bytes() :: pos_integer()
  def default_max_bytes, do: @default_max_bytes

  @doc """
  Make the starting state the turn's diff is taken against.

  Runs in `cwd` — the runtime's workspace — and returns the commit
  `since/3` compares to. Call it after provisioning and the seal and
  before the turn, so what provisioning wrote is the baseline rather than
  the agent's work.

  Never fatal to a caller that treats it as evidence: a box with no git on
  it answers `{:error, :git_unavailable}` and the record says so.
  """
  @spec baseline(Box.t(), String.t(), [{String.t(), String.t()}]) ::
          {:ok, baseline()} | {:error, error()}
  def baseline(%Box{} = box, cwd, env \\ []) do
    box
    |> exec(baseline_script(), [cwd | pathspecs()], env)
    |> from_baseline_exec(cwd)
  end

  @doc """
  Everything that changed in the workspace since `baseline`.

  Options:

    * `:max_bytes` — the patch's cap, default `#{@default_max_bytes}`. The
      file list is never capped: a truncated patch with a complete list of
      what it truncated is still evidence;
    * `:redact` — strings to replace with `[REDACTED]`. See the moduledoc:
      for Airlock this is the broker's session token, and nothing else;
    * `:env` — the environment the git commands run with.
  """
  @spec since(Box.t(), baseline(), keyword()) :: {:ok, t()} | {:error, error()}
  def since(%Box{} = box, %{cwd: cwd, ref: ref}, opts \\ []) do
    max_bytes = Keyword.get(opts, :max_bytes, @default_max_bytes)

    # One byte past the cap, so an exact fit is told from a truncation.
    args = [cwd, ref, Integer.to_string(max_bytes + 1) | pathspecs()]

    box
    |> exec(diff_script(), args, Keyword.get(opts, :env, []))
    |> from_diff_exec(cwd, max_bytes, Keyword.get(opts, :redact, []))
  end

  # ── the exec boundary ──────────────────────────────────────────────────────

  # `bash -c SCRIPT NAME ARGS…`: the workspace, the ref and the pathspecs
  # are positional parameters, never interpolated into the script, so a
  # path is data whatever it contains. The same discipline
  # `Fountain.SandboxFiles` uses, and the reason its scripts are fixed.
  # `-lc` rather than `-c`: the rest of Airlock's box scripts are login
  # shells, and git is on the image's `PATH` through the profile. Under
  # `-c` a box with git installed answers `:git_unavailable`, which is
  # honest but wrong.
  defp exec(box, script, args, env) do
    Box.exec(box, "bash", ["-lc", script, "airlock-changes" | args], env: env, timeout: @timeout)
  end

  defp pathspecs, do: Enum.map(@excludes, &":(exclude,glob)**/#{&1}/**")

  @doc false
  @spec from_baseline_exec(term(), String.t()) :: {:ok, baseline()} | {:error, error()}
  def from_baseline_exec({:ok, output, 0}, cwd) do
    case output |> to_string() |> String.trim() |> String.split("\n") |> List.last() do
      ref when is_binary(ref) and byte_size(ref) >= 7 -> {:ok, %{cwd: cwd, ref: ref}}
      _ -> {:error, {:unreadable, "the baseline commit was not a revision"}}
    end
  end

  def from_baseline_exec(result, _cwd), do: {:error, exec_error(result)}

  @doc false
  @spec from_diff_exec(term(), String.t(), pos_integer(), [String.t()]) ::
          {:ok, t()} | {:error, error()}
  def from_diff_exec({:ok, output, 0}, cwd, max_bytes, redact) do
    case String.split(to_string(output), <<0o036>>, parts: 3) do
      [numstat, status, encoded] ->
        {:ok, diff(numstat, status, encoded, cwd, max_bytes, redact)}

      _ ->
        {:error, {:unreadable, "the diff did not come back in three parts"}}
    end
  end

  def from_diff_exec(result, _cwd, _max_bytes, _redact), do: {:error, exec_error(result)}

  defp exec_error({:ok, _output, @exit_no_git}), do: :git_unavailable
  defp exec_error({:ok, _output, @exit_workspace_missing}), do: :workspace_missing
  defp exec_error({:ok, _output, @exit_not_repository}), do: :not_a_repository
  defp exec_error({:ok, output, @exit_git_failed}), do: {:git_failed, tail(output)}
  defp exec_error({:ok, output, _code}), do: {:git_failed, tail(output)}
  defp exec_error({:error, reason}), do: {:box, reason}
  defp exec_error(other), do: {:unreadable, inspect(other)}

  defp diff(numstat, status, encoded, cwd, max_bytes, redact) do
    bytes = decode(encoded)
    truncated = byte_size(bytes) > max_bytes
    kept = binary_part(bytes, 0, min(byte_size(bytes), max_bytes))

    %{
      cwd: cwd,
      files: merge(parse_numstat(numstat), parse_status(status)),
      diff: kept |> to_text() |> redact(redact),
      truncated: truncated,
      excluded: @excludes
    }
  end

  # ── parsing ────────────────────────────────────────────────────────────────

  # `--numstat -z`: `added \t removed \t path` per NUL-terminated record.
  # A rename ends the record after the tab and follows it with two more
  # records, the old path and the new — which is git's documented `-z`
  # shape and the reason this walks rather than maps.
  defp parse_numstat(section) do
    section |> records() |> walk_numstat([])
  end

  defp walk_numstat([], acc), do: Enum.reverse(acc)

  defp walk_numstat([record | rest], acc) do
    case String.split(record, "\t", parts: 3) do
      [added, removed, ""] ->
        case rest do
          [_old, new | tail] -> walk_numstat(tail, [{new, count(added), count(removed)} | acc])
          _ -> Enum.reverse(acc)
        end

      [added, removed, path] ->
        walk_numstat(rest, [{path, count(added), count(removed)} | acc])

      _ ->
        walk_numstat(rest, acc)
    end
  end

  # `--name-status -z`: the code, then the path — or, for a rename or a
  # copy, the code then the old path then the new one.
  defp parse_status(section), do: section |> records() |> walk_status([])

  defp walk_status([], acc), do: Enum.reverse(acc)

  defp walk_status([code | rest], acc) do
    if String.starts_with?(code, ["R", "C"]) do
      case rest do
        [_old, new | tail] -> walk_status(tail, [{new, status_word(code)} | acc])
        _ -> Enum.reverse(acc)
      end
    else
      case rest do
        [path | tail] -> walk_status(tail, [{path, status_word(code)} | acc])
        [] -> Enum.reverse(acc)
      end
    end
  end

  defp records(section), do: section |> String.split(<<0>>) |> Enum.reject(&(&1 == ""))

  # The two lists name the same files; the counts are the interesting half
  # and the status is what makes a 12-line file read as *new* rather than
  # changed. A file in one and not the other keeps what it has.
  defp merge(counts, statuses) do
    by_path = Map.new(statuses)

    Enum.map(counts, fn {path, added, removed} ->
      %{
        path: path,
        status: Map.get(by_path, path, "changed"),
        added: added,
        removed: removed
      }
    end)
  end

  defp status_word("A" <> _), do: "added"
  defp status_word("M" <> _), do: "modified"
  defp status_word("D" <> _), do: "deleted"
  defp status_word("R" <> _), do: "renamed"
  defp status_word("C" <> _), do: "copied"
  defp status_word("T" <> _), do: "typechange"
  defp status_word(other), do: other

  # `-` is git for "binary, no line count". Not zero — a binary file that
  # changed did change, and saying `0` would say it did not.
  defp count("-"), do: nil

  defp count(value) do
    case Integer.parse(value) do
      {n, ""} when n >= 0 -> n
      _ -> nil
    end
  end

  defp decode(encoded) do
    case Base.decode64(encoded, ignore: :whitespace) do
      {:ok, bytes} -> bytes
      :error -> ""
    end
  end

  # A diff is text by construction — git says "Binary files differ" for
  # the rest — but a latin-1 source file makes an invalid UTF-8 hunk.
  # Recode it rather than refuse the whole diff.
  defp to_text(bytes) do
    if String.valid?(bytes),
      do: bytes,
      else: :unicode.characters_to_binary(bytes, :latin1)
  end

  defp redact(text, []), do: text

  defp redact(text, values) do
    # Longest first, so a value containing another is replaced whole.
    values
    |> Enum.filter(&(is_binary(&1) and byte_size(&1) >= 8))
    |> Enum.uniq()
    |> Enum.sort_by(&byte_size/1, :desc)
    |> case do
      [] -> text
      values -> :binary.replace(text, values, "[REDACTED]", [:global])
    end
  end

  defp tail(output), do: output |> to_string() |> String.slice(-500..-1//1) |> to_string()

  # ── the scripts ────────────────────────────────────────────────────────────

  # `git init` if there is no repository, then commit everything that is
  # there. `--allow-empty` because a workspace provisioning left untouched
  # is still a starting state, and a baseline that failed for being empty
  # would take the tab away from exactly the runs that changed nothing.
  defp baseline_script do
    ~s"""
    d=$1
    shift
    command -v git >/dev/null 2>&1 || exit #{@exit_no_git}
    [ -d "$d" ] || exit #{@exit_workspace_missing}
    cd -- "$d" 2>/dev/null || exit #{@exit_workspace_missing}
    if [ ! -e .git ]; then
      git init -q >/dev/null 2>&1 || exit #{@exit_git_failed}
    fi
    git #{Enum.join(@git_identity, " ")} add -A -- . "$@" >/dev/null 2>&1 \
      || exit #{@exit_git_failed}
    git #{Enum.join(@git_identity, " ")} commit -q --allow-empty \
      -m "airlock baseline" >/dev/null 2>&1 || exit #{@exit_git_failed}
    git rev-parse HEAD
    """
  end

  # Three sections separated by RS (0o036), because NUL is already the
  # separator *inside* the first two: the file counts, the file statuses,
  # and the patch base64-encoded so its bytes survive whichever transport
  # an adapter streams stdout over.
  defp diff_script do
    ~s"""
    d=$1
    base=$2
    n=$3
    shift 3
    command -v git >/dev/null 2>&1 || exit #{@exit_no_git}
    [ -d "$d" ] || exit #{@exit_workspace_missing}
    cd -- "$d" 2>/dev/null || exit #{@exit_workspace_missing}
    git rev-parse --show-toplevel >/dev/null 2>&1 || exit #{@exit_not_repository}
    git #{Enum.join(@git_identity, " ")} add -A -- . "$@" >/dev/null 2>&1 \
      || exit #{@exit_git_failed}
    git --no-pager --no-optional-locks diff --cached --numstat -z "$base" -- . "$@" \
      || exit #{@exit_git_failed}
    printf '\\036'
    git --no-pager --no-optional-locks diff --cached --name-status -z "$base" -- . "$@" \
      || exit #{@exit_git_failed}
    printf '\\036'
    git --no-pager --no-optional-locks diff --cached --no-color --no-ext-diff "$base" \
      -- . "$@" | head -c "$n" | base64
    """
  end
end
