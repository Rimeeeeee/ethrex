#!/usr/bin/env bash
set -euo pipefail

# Build the local ethrex image, launch the Hegota network, then add the two
# ethrex-only future activation timestamps to every execution client's genesis
# file. The ethereum-package generator does not know these fields yet.

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
ENCLAVE="${ENCLAVE:-eip8304-utxo}"
IMAGE_TAG="${IMAGE_TAG:-local}"
IMAGE="ethrex:${IMAGE_TAG}"
CONFIG="${KURTOSIS_CONFIG_FILE:-fixtures/networks/hegota-devnet.yaml}"
ACTIVATION_LEAD_SECONDS="${ACTIVATION_LEAD_SECONDS:-900}"
UTXO_DELAY_SECONDS="${UTXO_DELAY_SECONDS:-60}"
SKIP_IMAGE_BUILD="${SKIP_IMAGE_BUILD:-0}"
KURTOSIS_BIN="${KURTOSIS_BIN:-kurtosis}"

for command in docker make python3; do
  command -v "$command" >/dev/null || {
    echo "missing required command: $command" >&2
    exit 1
  }
done
if ! docker info >/dev/null 2>&1; then
  echo "Docker daemon is unavailable or unhealthy; start/restart Docker Desktop first" >&2
  exit 1
fi
if [[ "$KURTOSIS_BIN" == */* ]]; then
  [[ -x "$KURTOSIS_BIN" ]] || { echo "Kurtosis is not executable: $KURTOSIS_BIN" >&2; exit 1; }
elif ! command -v "$KURTOSIS_BIN" >/dev/null; then
  echo "missing required command: $KURTOSIS_BIN (set KURTOSIS_BIN to its executable path)" >&2
  exit 1
fi

cd "$ROOT"
if [[ "$SKIP_IMAGE_BUILD" != "1" ]]; then
  make build-image TAG="$IMAGE_TAG"
elif ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "SKIP_IMAGE_BUILD=1 was requested, but image $IMAGE does not exist" >&2
  echo "Build it successfully first: make build-image TAG=$IMAGE_TAG" >&2
  exit 1
fi
make checkout-ethereum-package
ethereum_package_revision="$(git -C ethereum-package rev-parse HEAD)"
ethereum_package="${KURTOSIS_PACKAGE:-github.com/ethpandaops/ethereum-package@$ethereum_package_revision}"

# The selected tag and the image in the args file must agree. The checked-in
# config uses ethrex:local; alternate tags require an alternate args file.
if [[ "$IMAGE" != "ethrex:local" ]] && grep -q 'el_image: ethrex:local' "$CONFIG"; then
  echo "$CONFIG selects ethrex:local but IMAGE_TAG=$IMAGE_TAG" >&2
  exit 1
fi

# Use the pinned remote locator by default. The upstream package contains a
# Linux symlink under .agents; the native Windows Kurtosis CLI sees that link
# as an inaccessible NTFS junction when hashing a local WSL checkout.
"$KURTOSIS_BIN" run --enclave "$ENCLAVE" "$ethereum_package" --args-file "$CONFIG"

mapfile -t el_containers < <(
  docker ps -q \
    --filter "label=com.kurtosistech.enclave-name=$ENCLAVE" \
    --filter "ancestor=$IMAGE"
)
if [[ "${#el_containers[@]}" -ne 3 ]]; then
  echo "expected 3 ethrex EL containers in $ENCLAVE, found ${#el_containers[@]}" >&2
  printf '%s\n' "${el_containers[@]}" >&2
  exit 1
fi

eip8304_time="$(($(date +%s) + ACTIVATION_LEAD_SECONDS))"
utxo_frames_time="$((eip8304_time + UTXO_DELAY_SECONDS))"
patch_dir="$(mktemp -d)"
trap 'rm -rf -- "$patch_dir"' EXIT

for container in "${el_containers[@]}"; do
  source_genesis="$patch_dir/$container.json"
  patched_genesis="$patch_dir/$container-patched.json"
  docker cp "$container:/network-configs/genesis.json" "$source_genesis"
  python3 scripts/eip8304-utxo-devnet/patch-genesis.py \
    "$source_genesis" "$patched_genesis" "$eip8304_time" "$utxo_frames_time"
  docker cp "$patched_genesis" "$container:/network-configs/genesis.json"
done

# Both fields are consensus inputs and invisible to ForkId. Restart all ELs
# back-to-back while both timestamps are still in the future.
docker restart "${el_containers[@]}" >/dev/null

echo
echo "EIP-8304 + EIP-8312 devnet started"
echo "  enclave:             $ENCLAVE"
echo "  image:               $IMAGE"
echo "  ethereum package:    $ethereum_package"
echo "  eip8304Time:         $eip8304_time"
echo "  utxoFramesTime:      $utxo_frames_time"
echo "  index address:       0x0000000000000000000000000000000000008304"
echo "  UTXO vault:          0x0000000000000000000000000000000000008312"
echo
echo "Find the published RPC endpoint with:"
echo "  $KURTOSIS_BIN enclave inspect $ENCLAVE"
echo
echo "Then verify it with:"
echo "  scripts/eip8304-utxo-devnet/verify-devnet.sh http://127.0.0.1:<rpc-port>"

"$KURTOSIS_BIN" enclave inspect "$ENCLAVE"
