# deadhop service and its crates: rustfmt, clippy (warnings are errors) and tests
# with 100% line and function coverage enforced, the service and each crate.
check:
    cargo fmt --check
    cargo clippy --all-targets -- -D warnings
    cargo llvm-cov --all-targets --show-missing-lines --fail-under-lines 100 --fail-under-functions 100
    for c in tlspin net cvm electrum common netengine; do \
        (cd crates/$c && cargo fmt --check && cargo clippy --all-targets -- -D warnings \
            && cargo llvm-cov --show-missing-lines --fail-under-lines 100 --fail-under-functions 100) || exit 1; \
    done

# Tests only, with the coverage gate
test:
    cargo llvm-cov --all-targets --show-missing-lines --fail-under-lines 100 --fail-under-functions 100

# Read-only check of a real Electrum server; reads its address from .env.local
live-electrum:
    set -a && . ./.env.local && set +a && cargo test --test live_electrum -- --ignored --nocapture
