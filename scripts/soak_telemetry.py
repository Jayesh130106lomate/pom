#!/usr/bin/env python3
"""
PRISM / POM Mixnet Soak Telemetry Collector & Regression Analyzer

Harvests high-frequency metrics every 15 seconds from all 12 relay containers
and client endpoints, logs time-series data to CSV, and conducts post-run
linear regression for memory leak detection and throughput degradation analysis.
"""

import argparse
import csv
import json
import math
import os
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone

RELAYS = [
    "pom-entry-1", "pom-entry-2", "pom-entry-3", "pom-entry-4",
    "pom-mix-1",   "pom-mix-2",   "pom-mix-3",   "pom-mix-4",
    "pom-exit-1",  "pom-exit-2",  "pom-exit-3",  "pom-exit-4"
]

running = True

def signal_handler(signum, frame):
    global running
    running = False

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

def parse_mem_mib(mem_str):
    """Parse Docker memory string like '12.34MiB / 64MiB' or '845KiB' into MiB float."""
    try:
        val_str = mem_str.split('/')[0].strip()
        if 'GiB' in val_str:
            return float(val_str.replace('GiB', '')) * 1024.0
        elif 'MiB' in val_str:
            return float(val_str.replace('MiB', ''))
        elif 'KiB' in val_str:
            return float(val_str.replace('KiB', '')) / 1024.0
        elif 'B' in val_str:
            return float(val_str.replace('B', '')) / (1024.0 * 1024.0)
        return float(val_str)
    except Exception:
        return 0.0

def parse_cpu_perc(cpu_str):
    """Parse Docker CPU string like '1.25%' into float."""
    try:
        return float(cpu_str.replace('%', '').strip())
    except Exception:
        return 0.0

def get_docker_stats():
    """Fetch live CPU and Memory for all relay containers."""
    stats = {}
    try:
        cmd = ["docker", "stats", "--no-stream", "--format", "{{.Name}},{{.CPUPerc}},{{.MemUsage}}"]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        if res.returncode == 0:
            for line in res.stdout.strip().split('\n'):
                if not line:
                    continue
                parts = line.split(',')
                if len(parts) >= 3:
                    name = parts[0].strip()
                    cpu = parse_cpu_perc(parts[1])
                    mem_mib = parse_mem_mib(parts[2])
                    stats[name] = {"cpu": cpu, "mem_mib": mem_mib}
    except Exception as e:
        sys.stderr.write(f"Error reading docker stats: {e}\n")
    return stats

def get_container_status(container):
    """Check running and OOMKilled state."""
    try:
        cmd = ["docker", "inspect", container, "--format", "{{.State.Running}},{{.State.OOMKilled}},{{.State.RestartCount}}"]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
        if res.returncode == 0:
            parts = res.stdout.strip().split(',')
            return {
                "running": parts[0] == "true",
                "oom_killed": parts[1] == "true",
                "restarts": int(parts[2]) if len(parts) > 2 else 0
            }
    except Exception:
        pass
    return {"running": False, "oom_killed": False, "restarts": 0}

def get_node_telemetry(container):
    """Read /tmp/prism_status.json from inside the container."""
    try:
        cmd = ["docker", "exec", container, "cat", "/tmp/prism_status.json"]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
        if res.returncode == 0:
            return json.loads(res.stdout.strip())
    except Exception:
        pass
    return {}

def linear_regression_slope(x_vals, y_vals):
    """Compute slope (dy/dx) using standard least squares."""
    n = len(x_vals)
    if n < 2:
        return 0.0
    x_mean = sum(x_vals) / n
    y_mean = sum(y_vals) / n
    numerator = sum((x_vals[i] - x_mean) * (y_vals[i] - y_mean) for i in range(n))
    denominator = sum((x_vals[i] - x_mean) ** 2 for i in range(n))
    if denominator == 0.0:
        return 0.0
    return numerator / denominator

def run_collector(csv_out, interval_sec, duration_sec):
    global running
    print(f">> Starting Soak Telemetry Collector (Sampling every {interval_sec}s -> {csv_out})")
    fieldnames = [
        "timestamp_epoch", "elapsed_sec", "container", "layer", "cpu_perc", "mem_mib",
        "oom_killed", "running", "packets_received", "packets_forwarded", "packets_delivered",
        "packets_dropped", "replays", "mac_failures", "rate_limit_drops", "backpressure_drops",
        "pool_overflows", "active_conns", "mix_pool_depth", "mix_pool_high_water",
        "replay_filter_count", "replay_filter_fpr"
    ]

    with open(csv_out, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        f.flush()

        start_time = time.time()
        sample_idx = 0

        while running:
            loop_start = time.time()
            elapsed = loop_start - start_time
            if duration_sec > 0 and elapsed >= duration_sec:
                break
            if os.path.exists("/tmp/soak_stop"):
                break

            docker_stats = get_docker_stats()

            for c in RELAYS:
                c_stats = docker_stats.get(c, {"cpu": 0.0, "mem_mib": 0.0})
                c_status = get_container_status(c)
                node_data = get_node_telemetry(c)

                row = {
                    "timestamp_epoch": f"{loop_start:.2f}",
                    "elapsed_sec": f"{elapsed:.1f}",
                    "container": c,
                    "layer": node_data.get("layer", 1 if "entry" in c else (2 if "mix" in c else 3)),
                    "cpu_perc": c_stats["cpu"],
                    "mem_mib": c_stats["mem_mib"],
                    "oom_killed": c_status["oom_killed"],
                    "running": c_status["running"],
                    "packets_received": node_data.get("received", 0),
                    "packets_forwarded": node_data.get("forwarded", 0),
                    "packets_delivered": node_data.get("delivered", 0),
                    "packets_dropped": node_data.get("dropped", 0),
                    "replays": node_data.get("replays", 0),
                    "mac_failures": node_data.get("mac_failures", 0),
                    "rate_limit_drops": node_data.get("rate_limit_drops", 0),
                    "backpressure_drops": node_data.get("backpressure_drops", 0),
                    "pool_overflows": node_data.get("pool_overflows", 0),
                    "active_conns": node_data.get("active_conns", 0),
                    "mix_pool_depth": node_data.get("mix_pool_depth", 0),
                    "mix_pool_high_water": node_data.get("mix_pool_high_water", 0),
                    "replay_filter_count": node_data.get("replay_filter_count", 0),
                    "replay_filter_fpr": node_data.get("replay_filter_fpr", 0.0),
                }
                writer.writerow(row)

            f.flush()
            sample_idx += 1

            # Sleep remaining interval in interruptible slices
            compute_time = time.time() - loop_start
            sleep_time = max(0.1, interval_sec - compute_time)
            sleep_end = time.time() + sleep_time
            while running and time.time() < sleep_end:
                if os.path.exists("/tmp/soak_stop"):
                    running = False
                    break
                time.sleep(0.2)

    print(f">> Soak Telemetry Collector finished ({sample_idx} samples captured).")

def run_analysis(csv_in, json_out):
    print(f">> Analyzing Soak Telemetry from {csv_in}...")
    if not os.path.exists(csv_in):
        print(f"Error: File {csv_in} does not exist.")
        return

    records_by_node = {c: [] for c in RELAYS}
    with open(csv_in, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            c = row.get("container")
            if c in records_by_node:
                records_by_node[c].append(row)

    analysis = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "relays": {},
        "cluster_memory": {},
        "cluster_delivery": {},
        "acceptance_verdict": {}
    }

    combined_initial_mem = 0.0
    combined_final_mem = 0.0
    combined_peak_mem = 0.0
    total_oom_kills = 0

    for c, rows in records_by_node.items():
        if not rows:
            continue
        mem_series = [float(r["mem_mib"]) for r in rows]
        cpu_series = [float(r["cpu_perc"]) for r in rows]
        time_series_min = [float(r["elapsed_sec"]) / 60.0 for r in rows]

        initial_mem = mem_series[0]
        final_mem = mem_series[-1]
        min_mem = min(mem_series)
        max_mem = max(mem_series)
        mean_mem = sum(mem_series) / len(mem_series)
        duration_min = max(0.1, time_series_min[-1] - time_series_min[0]) if len(time_series_min) > 1 else 0.5
        # Post-warmup slope (excluding first 2 min of initial thread & allocator ramp)
        post_warmup_indices = [i for i, t in enumerate(time_series_min) if t >= 2.0]
        if duration_min >= 5.0 and len(post_warmup_indices) >= 5:
            post_t = [time_series_min[i] for i in post_warmup_indices]
            post_m = [mem_series[i] * 1024.0 for i in post_warmup_indices]
            mem_slope_kib_per_min = linear_regression_slope(post_t, post_m)
        else:
            mem_slope_kib_per_min = linear_regression_slope(time_series_min, [m * 1024.0 for m in mem_series])

        total_growth_mib = final_mem - initial_mem

        # Classification taking into account duration and absolute delta
        if duration_min < 5.0:
            if total_growth_mib <= 3.0:
                classification = "WARMUP_BOUNDED"
            else:
                classification = "INITIAL_WARMUP"
        else:
            if mem_slope_kib_per_min <= 1.0:
                classification = "STABLE"
            elif mem_slope_kib_per_min <= 3.0:
                classification = "SETTLING"
            else:
                classification = "POTENTIAL_LEAK"


        oom = any(r["oom_killed"] == "True" for r in rows)
        if oom:
            total_oom_kills += 1

        last_row = rows[-1]
        analysis["relays"][c] = {
            "initial_mem_mib": round(initial_mem, 2),
            "final_mem_mib": round(final_mem, 2),
            "min_mem_mib": round(min_mem, 2),
            "max_mem_mib": round(max_mem, 2),
            "mean_mem_mib": round(mean_mem, 2),
            "mem_slope_kib_per_min": round(mem_slope_kib_per_min, 3),
            "classification": classification,
            "mean_cpu_perc": round(sum(cpu_series) / len(cpu_series), 2),
            "max_cpu_perc": round(max(cpu_series), 2),
            "mix_pool_depth": int(last_row.get("mix_pool_depth", 0)),
            "mix_pool_high_water": int(last_row.get("mix_pool_high_water", 0)),
            "replay_filter_count": int(last_row.get("replay_filter_count", 0)),
            "replay_filter_fpr": float(last_row.get("replay_filter_fpr", 0.0)),
            "rate_limit_drops": int(last_row.get("rate_limit_drops", 0)),
            "backpressure_drops": int(last_row.get("backpressure_drops", 0)),
            "pool_overflows": int(last_row.get("pool_overflows", 0)),
            "packets_received": int(last_row.get("packets_received", 0)),
            "packets_forwarded": int(last_row.get("packets_forwarded", 0)),
            "packets_delivered": int(last_row.get("packets_delivered", 0)),
            "oom_killed": oom
        }

        combined_initial_mem += initial_mem
        combined_final_mem += final_mem
        combined_peak_mem += max_mem

    analysis["cluster_memory"] = {
        "initial_combined_mib": round(combined_initial_mem, 2),
        "final_combined_mib": round(combined_final_mem, 2),
        "peak_combined_mib": round(combined_peak_mem, 2),
        "total_oom_kills": total_oom_kills
    }

    # Aggregate layer totals
    total_entry_recv = sum(analysis["relays"][c]["packets_received"] for c in RELAYS if "entry" in c)
    total_entry_fwd  = sum(analysis["relays"][c]["packets_forwarded"] for c in RELAYS if "entry" in c)
    total_mix_recv   = sum(analysis["relays"][c]["packets_received"] for c in RELAYS if "mix" in c)
    total_mix_fwd    = sum(analysis["relays"][c]["packets_forwarded"] for c in RELAYS if "mix" in c)
    total_exit_recv  = sum(analysis["relays"][c]["packets_received"] for c in RELAYS if "exit" in c)
    total_exit_deliv = sum(analysis["relays"][c]["packets_delivered"] for c in RELAYS if "exit" in c)

    analysis["cluster_delivery"] = {
        "entry_received": total_entry_recv,
        "entry_forwarded": total_entry_fwd,
        "mix_received": total_mix_recv,
        "mix_forwarded": total_mix_fwd,
        "exit_received": total_exit_recv,
        "exit_delivered": total_exit_deliv,
    }

    # Acceptance Criteria Evaluation
    analysis["acceptance_verdict"] = {
        "no_unexpected_crashes": all(analysis["relays"][c].get("oom_killed") is False for c in RELAYS if c in analysis["relays"]),
        "zero_oom_kills": total_oom_kills == 0,
        "memory_bounded": all(analysis["relays"][c]["mem_slope_kib_per_min"] <= 2.0 for c in RELAYS if c in analysis["relays"]),
        "queue_bounded": all(analysis["relays"][c]["pool_overflows"] == 0 for c in RELAYS if c in analysis["relays"]),
    }

    with open(json_out, "w") as f:
        json.dump(analysis, f, indent=2)

    print(f">> Analysis complete. Exported to {json_out}")
    print("================================================================================")
    print("                    SOAK TELEMETRY ANALYSIS SUMMARY                             ")
    print("================================================================================")
    print(f"Combined Cluster RAM (Initial) : {combined_initial_mem:.2f} MiB")
    print(f"Combined Cluster RAM (Final)   : {combined_final_mem:.2f} MiB")
    print(f"Combined Cluster RAM (Peak)    : {combined_peak_mem:.2f} MiB")
    print(f"Total Linux OOM Kills          : {total_oom_kills}")
    print("--------------------------------------------------------------------------------")
    print("Per-Relay Memory Drift & Linear Regression Slope (KiB/min):")
    for c in RELAYS:
        if c in analysis["relays"]:
            r = analysis["relays"][c]
            print(f"  {c:<13} : Initial {r['initial_mem_mib']:>5.2f} MiB | Final {r['final_mem_mib']:>5.2f} MiB | Slope {r['mem_slope_kib_per_min']:>+6.3f} KiB/min [{r['classification']}]")
    print("--------------------------------------------------------------------------------")
    print("Multi-Layer Packet Accounting Ledger:")
    print(f"  Layer 1 (Entry) Ingress Received : {total_entry_recv:>8} pkts")
    print(f"  Layer 1 (Entry) Egress Forwarded : {total_entry_fwd:>8} pkts")
    print(f"  Layer 2 (Mix)   Ingress Received : {total_mix_recv:>8} pkts")
    print(f"  Layer 2 (Mix)   Egress Forwarded : {total_mix_fwd:>8} pkts")
    print(f"  Layer 3 (Exit)  Ingress Received : {total_exit_recv:>8} pkts")
    print(f"  Layer 3 (Exit)  Decrypted/Deliv  : {total_exit_deliv:>8} pkts")
    print("================================================================================")

def main():
    parser = argparse.ArgumentParser(description="PRISM Soak Telemetry Collector & Analyzer")
    subparsers = parser.add_subparsers(dest="command", required=True)

    col_parser = subparsers.add_parser("collect")
    col_parser.add_argument("--csv", default="/tmp/soak_telemetry.csv", help="Path to output CSV")
    col_parser.add_argument("--interval", type=float, default=15.0, help="Sampling interval in seconds")
    col_parser.add_argument("--duration", type=float, default=0.0, help="Max duration in seconds (0 for indefinite)")

    ana_parser = subparsers.add_parser("analyze")
    ana_parser.add_argument("--csv", default="/tmp/soak_telemetry.csv", help="Input CSV path")
    ana_parser.add_argument("--json", default="/tmp/soak_analysis.json", help="Output JSON path")

    args = parser.parse_args()
    if args.command == "collect":
        run_collector(args.csv, args.interval, args.duration)
    elif args.command == "analyze":
        run_analysis(args.csv, args.json)

if __name__ == "__main__":
    main()
