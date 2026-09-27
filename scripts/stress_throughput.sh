#!/usr/bin/env bash
set -e

# ==============================================================================
#             POM PRIVACY MIXNET: HIGH-THROUGHPUT STRESS BENCHMARK             
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PRISM_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/cargo_target}"

PACKETS="${1:-1000}"
CONCURRENCY="${2:-16}"
BATCH_SIZE="${3:-16}"

STRESS_BIN="$TARGET_DIR/release/pom-stress"

echo "================================================================================"
echo "          POM MIXNET HIGH-THROUGHPUT CONCURRENT STRESS BENCHMARK                "
echo "================================================================================"
echo "Target Packets : $PACKETS packets"
echo "Concurrency    : $CONCURRENCY worker tasks"
echo "Batch Size     : $BATCH_SIZE packets / batch"
echo "Packet Wire Size: 32,768 bytes fixed (Sphinx format)"
echo "Target Volume  : $(awk -v p="$PACKETS" 'BEGIN { printf "%.2f", (p * 32768) / 1048576 }') MB"
echo "================================================================================"
echo ""

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

# 3. Snapshot initial container stats
echo ">> Initial Docker Container Metrics (Before Stress):"
docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}"
echo ""

# 4. Execute the concurrent stress test
"$STRESS_BIN" -n "$PACKETS" -c "$CONCURRENCY" -b "$BATCH_SIZE"

# 5. Snapshot post-stress stats
echo ""
echo ">> Live Docker Container Metrics (After Stress):"
docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}"
echo ""

TOTAL_MEM=$(docker stats --no-stream --format "{{.MemUsage}}" | awk '{print $1}' | sed 's/MiB//g' | awk '{s+=$1} END {print s}')
echo ">> Total RAM used by ALL 6 mixnet nodes under stress: ~${TOTAL_MEM} MiB"
echo "   Average per relay: ~$(awk -v mem="$TOTAL_MEM" 'BEGIN { printf "%.2f", mem / 6 }') MiB RAM"
echo "================================================================================"
