#!/usr/bin/env bash
set -e

# ==============================================================================
#             POM PRIVACY MIXNET: HIGH-THROUGHPUT STRESS BENCHMARK             
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PRISM_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/cargo_target}"
STRESS_BIN="$TARGET_DIR/release/pom-stress"

# 1. Ensure Docker mixnet containers are up
RUNNING_COUNT=$(docker compose -f "$PRISM_DIR/docker-compose.yml" ps --filter "status=running" -q 2>/dev/null | wc -l)
if [ "$RUNNING_COUNT" -ne 6 ]; then
    echo ">> Starting Docker mixnet containers..."
    docker compose -f "$PRISM_DIR/docker-compose.yml" up -d
    sleep 2
fi

# 2. Ensure stress binary is built
if [ ! -f "$STRESS_BIN" ]; then
    echo ">> Building pom-stress release binary..."
    cargo build --release -p prism-benchmark --bin pom-stress --manifest-path "$PRISM_DIR/Cargo.toml"
fi

MODE="${1:-burst}"

if [ "$MODE" == "--sustained" ] || [ "$MODE" == "sustained" ]; then
    DURATION="${2:-10}"
    RATE="${3:-2000}"
    CONCURRENCY="${4:-16}"
    BATCH_SIZE="${5:-8}"
    
    echo "================================================================================"
    echo "          POM MIXNET: CONTINUOUS SUSTAINED THROUGHPUT BENCHMARK                 "
    echo "================================================================================"
    echo "Mode           : Continuous Sustained Stream (${DURATION}s window)"
    echo "Paced Rate     : ${RATE} packets/sec (~$(awk -v r="$RATE" 'BEGIN { printf "%.2f", (r * 32768) / 1048576 }') MB/s)"
    echo "Concurrency    : ${CONCURRENCY} worker tasks (batch size: ${BATCH_SIZE})"
    echo "Packet Size    : 32,768 bytes fixed (Sphinx format)"
    echo "================================================================================"
    echo ""
    echo ">> Live Container Metrics (Before Run):"
    docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}"
    echo ""
    
    "$STRESS_BIN" -d "$DURATION" -r "$RATE" -c "$CONCURRENCY" -b "$BATCH_SIZE"
    
    echo ""
    echo ">> Live Container Metrics (After Run):"
    docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}"
else
    PACKETS="${1:-1000}"
    CONCURRENCY="${2:-16}"
    BATCH_SIZE="${3:-16}"
    
    echo "================================================================================"
    echo "          POM MIXNET: CONCURRENCY INGRESS BURST BENCHMARK                       "
    echo "================================================================================"
    echo "Mode           : Concurrency Ingress Write Burst"
    echo "Target Packets : ${PACKETS} packets (~$(awk -v p="$PACKETS" 'BEGIN { printf "%.2f", (p * 32768) / 1048576 }') MB)"
    echo "Concurrency    : ${CONCURRENCY} worker tasks (batch size: ${BATCH_SIZE})"
    echo "Packet Size    : 32,768 bytes fixed (Sphinx format)"
    echo "================================================================================"
    echo ""
    echo ">> Live Container Metrics (Before Run):"
    docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}"
    echo ""
    
    "$STRESS_BIN" -n "$PACKETS" -c "$CONCURRENCY" -b "$BATCH_SIZE"
    
    echo ""
    echo ">> Live Container Metrics (After Run):"
    docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}"
fi

echo ""
TOTAL_MEM=$(docker stats --no-stream --format "{{.MemUsage}}" | awk '{print $1}' | sed 's/MiB//g' | awk '{s+=$1} END {print s}')
echo ">> Total RAM used by ALL 6 mixnet nodes: ~${TOTAL_MEM} MiB"
echo "   Average per relay: ~$(awk -v mem="$TOTAL_MEM" 'BEGIN { printf "%.2f", mem / 6 }') MiB RAM"
echo "================================================================================"
