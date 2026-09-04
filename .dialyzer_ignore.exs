# Warnings dialyzer is wrong about, each with why.
#
# Keep this list short and each entry justified. An ignore file is how a
# guard stops guarding: an entry that outlives its cause silences a real
# finding later.
[
  # `Mint.WebSocket.t()` is `@opaque`, and dialyzer drops the opaque
  # success branch of `Mint.WebSocket.new/4` when it crosses into this
  # module's inference — so it concludes `await_upgrade/3` can only fail
  # and calls the `{:ok, conn, websocket}` pattern unreachable.
  #
  # It is reachable: every test in test/airlock/box/endpoint_test.exs that
  # connects a daemon goes through it. Verified by breaking it — returning
  # an error from `await_upgrade/3`'s success path makes those tests die
  # with that error, so the branch is load-bearing and dialyzer is wrong.
  {"test/support/daemon_client.ex", :pattern_match}
]
