#!/usr/bin/env python3
"""
Multi-Layer Telemetry and Layer-by-Layer Verification for POM Mixnet.
Queries container metrics before and after benchmarks to measure exact
inter-layer packet traversal, drop reasons, and end-to-end delivery rates.
"""

import sys
import json
import subprocess
from typing import Dict, Any

CONTAINERS = [
    "pom-entry-1", "pom-entry-2", "pom-entry-3", "pom-entry-4",
    "pom-mix-1", "pom-mix-2", "pom-mix-3", "pom-mix-4",
    "pom-exit-1", "pom-exit-2", "pom-exit-3", "pom-exit-4"
]

def get_snapshot() -> Dict[str, Any]:
    snapshot = {}
    for name in CONTAINERS:
        try:
            res = subprocess.run(
                ["docker", "exec", name, "cat", "/tmp/prism_status.json"],
                capture_output=True, text=True, check=True
            )
            snapshot[name] = json.loads(res.stdout)
        except Exception as e:
            snapshot[name] = {"error": str(e)}
    return snapshot

def cmd_snapshot(file_path: str):
    data = get_snapshot()
    with open(file_path, "w") as f:
        json.dump(data, f, indent=2)
    print(f">> Snapshot captured for {len(data)} nodes -> {file_path}")

def cmd_diff(before_file: str, client_dispatched: int = 0):
    with open(before_file, "r") as f:
        before = json.load(f)
    after = get_snapshot()

    diffs = {}
    for name in CONTAINERS:
        b = before.get(name, {})
        a = after.get(name, {})
        if "error" in b or "error" in a:
            diffs[name] = {"error": "unavailable"}
            continue
        diffs[name] = {
            "layer": a.get("layer", 0),
            "received": a.get("received", 0) - b.get("received", 0),
            "forwarded": a.get("forwarded", 0) - b.get("forwarded", 0),
            "delivered": a.get("delivered", 0) - b.get("delivered", 0),
            "dropped": a.get("dropped", 0) - b.get("dropped", 0),
            "replays": a.get("replays", 0) - b.get("replays", 0),
            "rate_limit_drops": a.get("rate_limit_drops", 0) - b.get("rate_limit_drops", 0),
            "backpressure_drops": a.get("backpressure_drops", 0) - b.get("backpressure_drops", 0),
            "pool_overflows": a.get("pool_overflows", 0) - b.get("pool_overflows", 0),
        }

    # Layer aggregates
    l1_rx = sum(d.get("received", 0) for k, d in diffs.items() if "entry" in k)
    l1_fwd = sum(d.get("forwarded", 0) for k, d in diffs.items() if "entry" in k)
    l1_rep = sum(d.get("replays", 0) for k, d in diffs.items() if "entry" in k)
    l1_rl = sum(d.get("rate_limit_drops", 0) for k, d in diffs.items() if "entry" in k)

    l2_rx = sum(d.get("received", 0) for k, d in diffs.items() if "mix" in k)
    l2_fwd = sum(d.get("forwarded", 0) for k, d in diffs.items() if "mix" in k)
    l2_rep = sum(d.get("replays", 0) for k, d in diffs.items() if "mix" in k)
    l2_rl = sum(d.get("rate_limit_drops", 0) for k, d in diffs.items() if "mix" in k)

    l3_rx = sum(d.get("received", 0) for k, d in diffs.items() if "exit" in k)
    l3_deliv = sum(d.get("delivered", 0) for k, d in diffs.items() if "exit" in k)
    l3_rep = sum(d.get("replays", 0) for k, d in diffs.items() if "exit" in k)
    l3_rl = sum(d.get("rate_limit_drops", 0) for k, d in diffs.items() if "exit" in k)

    print("================================================================================")
    print("           POM MIXNET MULTI-LAYER TELEMETRY RECONCILIATION REPORT               ")
    print("================================================================================")
    print(f"Client Dispatched (Socket Writes) : {client_dispatched} packets")
    print("--------------------------------------------------------------------------------")
    print("Layer 1 (Entry Gateways - pom-entry-1..4):")
    print(f"  Ingress Received from Client     : {l1_rx} packets")
    print(f"  Forwarded to Mix Layer           : {l1_fwd} packets")
    print(f"  Replays Detected                 : {l1_rep}")
    print(f"  Rate Limit Drops                 : {l1_rl}")
    print("--------------------------------------------------------------------------------")
    print("Layer 2 (Mix Routers - pom-mix-1..4):")
    print(f"  Ingress Received from Entry      : {l2_rx} packets")
    print(f"  Forwarded to Exit Layer          : {l2_fwd} packets")
    print(f"  Replays Detected                 : {l2_rep}")
    print(f"  Rate Limit Drops                 : {l2_rl}")
    print("--------------------------------------------------------------------------------")
    print("Layer 3 (Exit Egress - pom-exit-1..4):")
    print(f"  Ingress Received from Mix        : {l3_rx} packets")
    print(f"  Payloads Decrypted & Delivered   : {l3_deliv} packets")
    print(f"  Replays Detected                 : {l3_rep}")
    print(f"  Rate Limit Drops                 : {l3_rl}")
    print("================================================================================")
    
    if client_dispatched > 0:
        delivery_rate = (l3_deliv / client_dispatched) * 100.0
        print(f"True End-to-End Delivery Rate      : {delivery_rate:.2f}% ({l3_deliv}/{client_dispatched})")
    elif l1_rx > 0:
        delivery_rate = (l3_deliv / l1_rx) * 100.0
        print(f"Mixnet Ingress-to-Exit Delivery Rate: {delivery_rate:.2f}% ({l3_deliv}/{l1_rx})")

    print("================================================================================\n")

    print("Per-Relay Node Breakdown:")
    print("┌──────────────┬──────────┬──────────┬───────────┬─────────┬─────────┬───────────┐")
    print("│ Relay Node   │ Received │Forwarded │ Delivered │ Replays │ RL-Drop │ Backpres. │")
    print("├──────────────┼──────────┼──────────┼───────────┼─────────┼─────────┼───────────┤")
    for name in CONTAINERS:
        d = diffs.get(name, {})
        print(f"│ {name:<12} │ {d.get('received',0):>8} │ {d.get('forwarded',0):>8} │ {d.get('delivered',0):>9} │ {d.get('replays',0):>7} │ {d.get('rate_limit_drops',0):>7} │ {d.get('backpressure_drops',0):>9} │")
    print("└──────────────┴──────────┴──────────┴───────────┴─────────┴─────────┴───────────┘")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: mixnet_telemetry.py snapshot <file> | diff <before_file> [client_sent]")
        sys.exit(1)
    cmd = sys.argv[1]
    if cmd == "snapshot":
        cmd_snapshot(sys.argv[2])
    elif cmd == "diff":
        before_file = sys.argv[2]
        client_sent = int(sys.argv[3]) if len(sys.argv) > 3 else 0
        cmd_diff(before_file, client_sent)
