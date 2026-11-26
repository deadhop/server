---
name: deadhop-server-develop
description: "Contribute to deadhop/server, the Rust payment service and the shared crates other deadhop tools build on. Use it whenever you change code in this repository: before writing a fix or feature, when `just check` or the 100% line and function coverage gate (cargo-llvm-cov) fails, when a snapshot test under tests/snapshots fails, when touching crates/* (consumed by deadhop/lnaddr and deadhop/wallet over git) or vendor/rmcp (patched into deadhop/lnaddr), when changing fixtures/route-patterns.json (copied into deadhop/js), or when preparing a pull request."
license: MIT
metadata:
  repository: https://github.com/deadhop/server
---

# Develop deadhop/server

This repository holds the payment service (`src/`) and the shared crates the other Rust
tools build on (`crates/`: `tlspin`, `net`, `cvm`, `electrum`, `common`, `netengine`), plus a
patched copy of rmcp in `vendor/rmcp`. Other repositories consume some of these files, so a
change here can need a follow-up elsewhere; the sections below say when.

## Requirements

Rust (CI uses the toolchain pinned in `.github/workflows/ci.yml`, with `rustfmt`, `clippy`
and `llvm-tools-preview`), [`just`](https://github.com/casey/just) and
[`cargo-llvm-cov`](https://github.com/taiki-e/cargo-llvm-cov).

## The gate

```sh
just check     # rustfmt --check, clippy -D warnings, tests at 100% lines and functions: the service, then each crate
just test      # the service's tests with the coverage gate only (crates are gated only by `just check`)
```

CI runs `just check` on every pull request. Run it before you push.

**Coverage is 100% of lines and 100% of functions, enforced** (`--fail-under-lines 100
--fail-under-functions 100`), for the service and separately for each crate (each crate has
its own `Cargo.lock` and is checked from its own directory). Every new line needs a test that
runs it. `--show-missing-lines` lists what is missed. The few conditions that cannot occur
in practice (bech32-encoding a valid key, for example) are `expect`s rather than untestable
error branches; keep it that rare.

**Tests are hermetic.** They use an in-process relay, a scripted Electrum server (plain and
TLS) and in-process SOCKS5, HTTP and HTTPS proxies. Never make a unit test reach the network
or a real node. The read-only checks against real servers are `#[ignore]`d integration tests
(`tests/live_electrum.rs`, `tests/live_i2p.rs`); `just live-electrum` runs the first against a
server named in a gitignored `.env.local` (`DEADHOP_TEST_ELECTRUM_HOST`,
`DEADHOP_TEST_ELECTRUM_PORT`). Never commit that file or a private host.

**Known flaky under load:** `app::tests::a_route_move_leaves_new_relays_to_the_restart_that_checks_them`
passes when run alone. Rerun once; a second failure is real.

## Snapshots

`tests/snapshots/*.json` record wire behaviour: the tool list and schemas, `get_settings`,
the stored settings form and the refusals clients see. A test that changes them fails and
writes what it found to `target/snapshots-actual/<name>.json`. If the change is intended,
copy that file over the committed one and say why in the pull request: clients depend on
these shapes.

## Changes that reach other repositories

Change the original here first, merge it, then follow up in the consumer.

| You changed | Who uses it | Follow-up |
| --- | --- | --- |
| `crates/*` public API | deadhop/lnaddr (`tlspin`, `cvm`, `net`, `common`, `netengine`) and deadhop/wallet (`common`, `electrum`, `net`, `tlspin`), by git from `main`, pinned by their `Cargo.lock` | After merge, run `just update-server-crates` in each consumer, adapt, open a pull request there |
| `vendor/rmcp` | deadhop/lnaddr repeats the `[patch.crates-io] rmcp` override (a `[patch]` does not pass down from a dependency) | `just update-server-crates` in lnaddr moves `rmcp` too |
| `fixtures/route-patterns.json` | deadhop/js `fixtures/route-patterns.json`, run by `@deadhop/network-ui`'s tests | Copy the file into deadhop/js in a pull request there |
| `tests/snapshots/get_settings_full.json` or `pool_health.json` | deadhop/js `fixtures/server-snapshots/`, parsed by `@deadhop/network-ui`'s schemas | Copy them into deadhop/js |

`fixtures/route-patterns.json` is a contract: the Rust router and the TypeScript network UI
both run its cases, so change both sides together. Keep the crates' public API stable where
you can; a breaking change means a pull request in every consumer.

`vendor/rmcp` is rmcp 1.8.0 with one backport (marked "deadhop backport" in
`src/service.rs`); its version must stay 1.8.0 for the patch to apply. See `vendor/README.md`.

## End to end

Real payments on regtest (bitcoind, Fulcrum, a relay and Chrome) run from a
[deadhop/stack](https://github.com/deadhop/stack) checkout, which builds this repository from
source: `just clone`, `just up`, `just server`, `just e2e`. Use it to check a change in the
running service; the deadhop-stack-regtest skill in deadhop/stack covers it.

## Docs, security and pull requests

- **Docs live in [deadhop/site](https://github.com/deadhop/site)**, not here. A new or renamed
  `DEADHOP_*` setting, command or tool needs a docs pull request there
  ([configuration](https://deadhop.run/docs/configuration.md), [commands](https://deadhop.run/docs/cli.md),
  [API](https://deadhop.run/docs/api.md)). Never invent a setting name in docs; grep `src/config.rs`.
- **`SECURITY.md`** is the threat model, the findings and their status, the remote-management
  rules and the open risks. A change to admission, proof of work, rate limits, key handling,
  remote management or the Electrum trust path should keep it true; update it in the same pull
  request.
- Never commit secrets, keys or real hosts. Use placeholders such as `npub1…` and `zpub6…`.
- Issues and pull requests for this code go to deadhop/server. Run `just check` before you push.
