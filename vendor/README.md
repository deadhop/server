# Vendored crates

## rmcp 1.8.0 (Apache-2.0)

The crates.io release of [rmcp](https://github.com/modelcontextprotocol/rust-sdk) 1.8.0, with one change in `src/service.rs` (marked "deadhop backport"): finished response-send tasks are reaped as they finish, as rmcp 3.x does. Without it, a server keeps every finished send until its session ends, and a ContextVM server session never ends (#46).

Every crate that builds rmcp uses this copy through `[patch.crates-io]`. The version stays 1.8.0 so that the patch applies.

Remove it, and the `[patch.crates-io]` sections, once `contextvm-sdk` depends on rmcp 3.x.
