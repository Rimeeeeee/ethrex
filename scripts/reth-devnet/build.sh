#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
: "${RETH_DIR:?Set RETH_DIR to the Reth frames-eips checkout (target ce5d5648f3)}"
BUILD_ROOT="${BUILD_ROOT:-$ROOT_DIR/.devnet-build}"
mkdir -p "$BUILD_ROOT"
BUILD_ROOT="$(cd "$BUILD_ROOT" && pwd)"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"
export CARGO_PROFILE_DEV_DEBUG=0
export CARGO_NET_GIT_FETCH_WITH_CLI=true
export LIBCLANG_PATH="${LIBCLANG_PATH:-/usr/lib/llvm-18/lib}"
repo_git() {
    local repo="$1"
    shift
    if git -C "$repo" "$@" 2>/dev/null; then
        return
    fi
    # Windows-created worktrees have Windows paths in .git; WSL's git cannot
    # resolve them, but the Windows git executable can read the same checkout.
    if command -v git.exe >/dev/null && command -v wslpath >/dev/null; then
        git.exe -C "$(wslpath -w "$repo")" "$@" | tr -d '\r'
    else
        return 1
    fi
}
RETH_SHA="$(repo_git "$RETH_DIR" rev-parse HEAD)"
if [[ "$RETH_SHA" != ce5d5648f31159f8b66c88a7d2056b43f9ef9aff ]]; then
    echo "Expected Reth frames-eips at ce5d5648f31159f8b66c88a7d2056b43f9ef9aff; found $RETH_SHA" >&2
    exit 1
fi
RETH_DIRTY=false
if [[ -n "$(repo_git "$RETH_DIR" status --porcelain)" ]]; then RETH_DIRTY=true; fi
(cd "$RETH_DIR"
    if ! git rev-parse HEAD >/dev/null 2>&1; then
        export VERGEN_GIT_SHA="$RETH_SHA" VERGEN_GIT_DESCRIBE="$RETH_SHA" VERGEN_GIT_DIRTY="$RETH_DIRTY"
    fi
    CARGO_TARGET_DIR="$BUILD_ROOT/reth/target" cargo +nightly build -p reth --bin reth \
        --no-default-features --features reth-revm/portable --locked)
(cd "$ROOT_DIR"; CARGO_TARGET_DIR="$BUILD_ROOT/ethrex/target" cargo +stable build -p ethrex --bin ethrex --locked)
echo "Run: uv run $ROOT_DIR/scripts/reth-devnet/devnet.py --reth $BUILD_ROOT/reth/target/debug/reth --ethrex $BUILD_ROOT/ethrex/target/debug/ethrex --keep-running"
