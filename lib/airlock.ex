defmodule Airlock do
  @moduledoc """
  Airlock runs a coding agent on a machine you chose, with credentials that
  machine never holds, and hands you a record of everything the agent did.

  `CLAUDE.md` is the brief and the boundary; `PLAN.md` is the order of work.
  `NOTES-M0.md` records what reading the pinned libraries changed about
  both.

  ## What is built

  M0 steps 1–3, and not the rest:

  | | |
  |---|---|
  | `Airlock.Box.Host` | the `Managoat.Runner.Host` a local box is presented through |
  | `Airlock.Box.Endpoint` | the WebSocket endpoint a runner daemon dials into |
  | `Airlock.Policy` | the policy file: parsed and validated |
  | `Airlock.Policy.Compile` | onto a `NetworkPolicy` and `Managoat.Broker.Rule`s |
  | `Airlock.Broker` | the proxy, and a session minted per run |
  | `Airlock.Egress` | the request log, as a telemetry handler |

  **Not yet built:** provisioning a box (M0 step 4), bringing up a runtime
  (5), sealing the box (6), driving a turn (7), the record as a file (8) or
  destroying the box (9). `Airlock.CLI` has no `run` command for that
  reason.

  **Blocked, not merely unwritten:** a *local* box needs a daemon that is
  not in any of the nine libraries, and `Managoat.Runner.Adapter` refuses
  `apply_network_policy/2` outright, so the local path cannot be sealed at
  all. `NOTES-M0.md` has both, with what it costs and what the options are.
  """

  @version Mix.Project.config()[:version]

  @doc "Airlock's version."
  @spec version() :: String.t()
  def version, do: @version
end
