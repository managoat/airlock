defmodule Airlock.Boxes do
  @moduledoc """
  Airlock's own boxes on a provider's account: find them, and destroy the
  ones a run did not.

  ## Why this exists

  `Airlock.Run` destroys the box on both the happy path and every error
  path, and that has been verified across real runs — four of them, three
  failures, nothing left behind. What it cannot cover is a **`SIGINT`**:
  the CLI process is gone before the `destroy` stage runs, and the box
  stays up. An orphaned Sprites box costs money for as long as nobody
  notices, and it holds a live proxy address — which is the part that
  matters here, because a box nobody is watching is exactly the box whose
  egress nobody is reading.

  So this is cheap insurance rather than a feature: `airlock boxes` says
  what is out there, and `airlock reap` destroys it.

  ## What counts as Airlock's

  `Airlock.Box.name_for/2` mints `airlock-<16 hex>` and nothing else does,
  so `ours?/1` matches exactly that shape and refuses everything else. It
  is deliberately narrow: `reap/2` destroys what it is given, and a
  prefix match on `airlock` would take `airlock-staging` with it.

  A runner box is **not** matched, and cannot be: its name carries the
  runner id (`runner-<32 hex>-<8 hex>`) because that is the only thing
  `Managoat.Sandbox` hands an adapter, so there is no room in it for a
  prefix. A local box is on the user's own machine anyway, which is the
  same reason the runner refuses to be sealed.

  ## Reaping is not the same as listing

  `list/1` reads and `reap/2` destroys, and `Airlock.CLI` will not do the
  second without `--yes` in as many words. A box that is still being
  worked on looks exactly like an orphan from out here — the account view
  is names, and `Managoat.Sandbox.get/1` reports a status but not a
  tenant — so the confirmation is the only thing standing between a
  reap and someone else's live run.
  """

  alias Airlock.Credentials
  alias Managoat.Sandbox

  @typedoc "One of Airlock's boxes, as the provider's account sees it."
  @type box :: %{name: String.t(), status: atom()}

  # `Airlock.Box.name_for/2`: "airlock-" <> 8 random bytes, hex.
  @name ~r/\Aairlock-[0-9a-f]{16}\z/

  @doc "Is this a name Airlock minted?"
  @spec ours?(String.t()) :: boolean()
  def ours?(name) when is_binary(name), do: Regex.match?(@name, name)
  def ours?(_name), do: false

  @doc """
  Every box on `provider`'s account that Airlock minted, with its status.

  `Managoat.Sandbox.list_all_names/1` refuses with `{:error, :truncated}`
  rather than returning a partial set that looks whole, and that is passed
  straight through: a reap run against half an account is worse than one
  that did not run.
  """
  @spec list(atom()) :: {:ok, [box()]} | {:error, term()}
  def list(provider) when is_atom(provider) do
    # Before the adapter is touched at all: it raises on a missing token
    # from inside the library, and a stack trace is not an answer to
    # "which boxes are out there". `NOTES-M0.md` §8.
    with :ok <- Credentials.provider_ready(provider),
         {:ok, names} <- Sandbox.list_all_names(provider) do
      boxes =
        names
        |> Enum.filter(&ours?/1)
        |> Enum.sort()
        |> Enum.map(&%{name: &1, status: status(provider, &1)})

      {:ok, boxes}
    end
  end

  @doc """
  Destroy `names` on `provider`, and say what happened to each.

  Every name is checked against `ours?/1` again here rather than trusted
  from the caller: this function destroys things, and the check is cheap.
  A name that is not Airlock's is `{:refused, name}` and is left alone.

  Already-gone is success — that is the `Managoat.Sandbox` contract, and
  it is what makes a reap safe to run twice.
  """
  @spec reap(atom(), [String.t()]) :: [{:ok | :refused | {:error, term()}, String.t()}]
  def reap(provider, names) when is_atom(provider) and is_list(names) do
    Enum.map(names, fn name ->
      if ours?(name) do
        {destroy(provider, name), name}
      else
        {:refused, name}
      end
    end)
  end

  defp destroy(provider, name) do
    provider |> Sandbox.build_handle(name) |> Sandbox.destroy()
  end

  # A box the provider will not describe is not a box to hide: `:unknown`
  # is one of the statuses `Managoat.Sandbox` documents, and a probe that
  # failed says the same thing for the purpose this list serves.
  defp status(provider, name) do
    case provider |> Sandbox.build_handle(name) |> Sandbox.get() do
      {:ok, %{status: status}} -> status
      {:error, _reason} -> :unknown
    end
  end
end
