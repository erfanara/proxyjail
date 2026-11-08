## Build

```bash
cargo check --workspace
cargo build --feature ebpf
```

Without the `ebpf` feature, the CLI starts the TCP runtime without an eBPF
event producer. This is useful for compiling and testing the runtime pieces,
but intercepted connections cannot be correlated or proxied.

## Current behavior

- eBPF events and accepted TCP sockets may arrive in either order.
- The coordinator stores unmatched items and expires them after
  `pending_timeout`.
- A matched connection opens `original_destination` and relays bytes in both
directions.
- The blocking relay uses two OS threads per active proxied connection.
- The internal standard-library `mpsc::channel` is unbounded. Before production,
  add queue limits, pending-item limits, and explicit overload behavior.
- The CLI currently does not implement child-process supervision or graceful
  cancellation of the eBPF polling loop; those are application-lifecycle tasks
  for a later iteration.

The listener defaults to `127.0.0.1:10000`.
