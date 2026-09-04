defmodule Airlock.Keychain do
  @moduledoc """
  Read secrets the workstation has already stored, rather than asking for
  them again.

  Ported from goatherd's `Goatherd.Keychain` — `CLAUDE.md` names it as the
  one module reusable as-is, and it is. The Sprites CLI and Claude Code
  both keep their credentials in the login keychain, and both are readable
  by the user who owns them, so a machine that already runs the tools
  Airlock drives needs no configuration.

  macOS only. Every lookup answers `:error` elsewhere, which callers treat
  as "not there" and fall back to an environment variable — so a Linux user
  sets `SPRITES_TOKEN` by hand and everything else behaves identically.
  """

  # Go's `99designs/keyring` — which the Sprites CLI and much of the Go
  # ecosystem use — stores any secret that is not plain ASCII as base64
  # behind this marker. macOS `security` hands back what was stored, so the
  # marker arrives verbatim, and an undecoded value fails authentication
  # with a 401 that says nothing about why.
  #
  # Not hypothetical: the Sprites token on this developer's machine is
  # stored wrapped. Verified 2026-09-03 — the raw item is 174 bytes with
  # the marker, and the token underneath is the four-segment
  # `org/id/key/secret`.
  @go_keyring_prefix "go-keyring-base64:"

  @doc """
  Read a generic password by service, optionally narrowed by account.

  `security` prints the secret on stdout, so this never goes through a
  shell string: the arguments are passed as a list and the output is never
  logged. A missing item is `:error`, not an exception — a caller
  distinguishing "no credential" from "broken keychain" would have nothing
  different to do.
  """
  @spec generic_password(String.t(), String.t() | nil) :: {:ok, String.t()} | :error
  def generic_password(service, account \\ nil) do
    if macos?() do
      case System.cmd("security", args(service, account), stderr_to_stdout: false) do
        {out, 0} -> {:ok, out |> String.trim() |> unwrap()}
        _ -> :error
      end
    else
      :error
    end
  rescue
    # `security` absent or not executable. Same answer as a missing item.
    ErlangError -> :error
  end

  @doc "True on Darwin, where the `security` binary exists."
  @spec macos?() :: boolean()
  def macos?, do: match?({:unix, :darwin}, :os.type())

  defp args(service, nil), do: ["find-generic-password", "-s", service, "-w"]

  defp args(service, account),
    do: ["find-generic-password", "-a", account, "-s", service, "-w"]

  defp unwrap(@go_keyring_prefix <> encoded) do
    case Base.decode64(encoded) do
      {:ok, decoded} -> decoded
      :error -> encoded
    end
  end

  defp unwrap(value), do: value
end
