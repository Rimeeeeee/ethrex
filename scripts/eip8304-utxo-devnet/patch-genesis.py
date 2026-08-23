#!/usr/bin/env python3
"""Add ethrex-only future activations to one generated genesis file."""
import json
import sys
from pathlib import Path


def main() -> None:
    if len(sys.argv) != 5:
        raise SystemExit("usage: patch-genesis.py <source> <target> <eip8304-time> <utxo-time>")
    source, target = map(Path, sys.argv[1:3])
    eip8304_time, utxo_time = map(int, sys.argv[3:5])
    if eip8304_time <= 0 or utxo_time <= eip8304_time:
        raise SystemExit("activation timestamps must be positive and UTXO must follow EIP-8304")
    genesis = json.loads(source.read_text(encoding="utf-8"))
    config = genesis.get("config")
    if not isinstance(config, dict):
        raise SystemExit(f"{source}: genesis config object is missing")
    config["eip8304Time"] = eip8304_time
    config["utxoFramesTime"] = utxo_time
    target.write_text(json.dumps(genesis, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
