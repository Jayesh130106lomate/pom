#!/usr/bin/env bash
# ==============================================================================
# PRISM / POM Mixnet WAN Impairment & Linux netem Controller
# ==============================================================================
# Injects kernel-level latency, jitter, and packet loss inside Docker containers
# using iproute2 / tc netem via container cap_add: [NET_ADMIN].
#
# Profiles:
#   Profile A: 15ms ± 3ms latency (normal dist), 0.5% loss
#   Profile B: 50ms ± 10ms latency (normal dist), 1.0% loss
# ==============================================================================

set -euo pipefail

CONTAINERS=(
    "pom-entry-1" "pom-entry-2" "pom-entry-3" "pom-entry-4"
    "pom-mix-1"   "pom-mix-2"   "pom-mix-3"   "pom-mix-4"
    "pom-exit-1"  "pom-exit-2"  "pom-exit-3"  "pom-exit-4"
)

PROFILE=""
DELAY=""
JITTER=""
LOSS=""
COMMAND="${1:-show}"

usage() {
    cat <<EOF
Usage: $0 <apply|reset|show|verify> [OPTIONS]

Commands:
  apply      Apply tc netem impairment to all 12 relay containers
  reset      Remove all tc netem impairment rules (restore full line-rate)
  show       Display current tc qdisc configuration on all containers
  verify     Run empirical ICMP/UDP probes across relay layers to measure RTT, jitter, and loss

Options for 'apply':
  --profile A       Profile A: 15ms ± 3ms delay, 0.5% loss
  --profile B       Profile B: 50ms ± 10ms delay, 1.0% loss
  --delay <time>    Custom delay (e.g. 20ms)
  --jitter <time>   Custom jitter (e.g. 5ms)
  --loss <pct>      Custom loss percentage (e.g. 0.5%)

EOF
    exit 1
}

shift || true
while [[ $# -gt 0 ]]; do
    case "$1" in
        --profile)
            PROFILE="$2"
            shift 2
            ;;
        --delay)
            DELAY="$2"
            shift 2
            ;;
        --jitter)
            JITTER="$2"
            shift 2
            ;;
        --loss)
            LOSS="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            usage
            ;;
    esac
done

if [[ "$PROFILE" == "A" || "$PROFILE" == "a" ]]; then
    DELAY="15ms"
    JITTER="3ms"
    LOSS="0.5%"
elif [[ "$PROFILE" == "B" || "$PROFILE" == "b" ]]; then
    DELAY="50ms"
    JITTER="10ms"
    LOSS="1.0%"
fi

apply_impairment() {
    if [[ -z "$DELAY" && -z "$LOSS" ]]; then
        echo "Error: Must specify --profile A/B or --delay/--loss parameters."
        exit 1
    fi

    echo "================================================================================"
    echo ">> Applying Kernel WAN Impairment to 12 POM Relays"
    echo "   Configured Latency : ${DELAY:-0ms} ± ${JITTER:-0ms} (normal distribution)"
    echo "   Configured Drop    : ${LOSS:-0%}"
    echo "================================================================================"

    local netem_args=""
    if [[ -n "$DELAY" ]]; then
        netem_args="delay $DELAY"
        if [[ -n "$JITTER" ]]; then
            netem_args="$netem_args $JITTER distribution normal"
        fi
    fi
    if [[ -n "$LOSS" ]]; then
        netem_args="$netem_args loss $LOSS"
    fi

    for c in "${CONTAINERS[@]}"; do
        if docker ps --format '{{.Names}}' | grep -q "^${c}$"; then
            docker exec "$c" tc qdisc del dev eth0 root 2>/dev/null || true
            docker exec "$c" tc qdisc add dev eth0 root netem $netem_args
            echo "   [OK] $c: netem $netem_args"
        else
            echo "   [SKIP] $c (container not running)"
        fi
    done

    echo ">> WAN impairment successfully applied."
}

reset_impairment() {
    echo "================================================================================"
    echo ">> Resetting WAN Impairment on all 12 POM Relays (Restoring Full Line Rate)"
    echo "================================================================================"

    for c in "${CONTAINERS[@]}"; do
        if docker ps --format '{{.Names}}' | grep -q "^${c}$"; then
            docker exec "$c" tc qdisc del dev eth0 root 2>/dev/null || true
            echo "   [OK] $c: netem rules removed"
        else
            echo "   [SKIP] $c (container not running)"
        fi
    done
    echo ">> Network impairment completely cleared."
}

show_impairment() {
    echo "================================================================================"
    echo ">> Active Traffic Control (tc qdisc) Status Across Relays"
    echo "================================================================================"
    for c in "${CONTAINERS[@]}"; do
        if docker ps --format '{{.Names}}' | grep -q "^${c}$"; then
            local status
            status=$(docker exec "$c" tc qdisc show dev eth0 2>/dev/null || echo "tc failed")
            printf "   %-15s : %s\n" "$c" "$status"
        fi
    done
}

verify_impairment() {
    echo "================================================================================"
    echo ">> Empirical WAN Impairment Measurement (Probe Verification)"
    echo "================================================================================"
    echo "Sending 20 diagnostic probes between layers to measure empirical RTT, jitter & drop..."

    # Probe 1: Hop 1 (Entry-1 -> Mix-1: 172.28.0.11 -> 172.28.0.21)
    echo -n "   [Probe 1] Entry-1 (172.28.0.11) -> Mix-1 (172.28.0.21): "
    local probe1_raw
    probe1_raw=$(docker exec pom-entry-1 ping -c 20 -i 0.1 172.28.0.21 2>&1 || true)
    local probe1_stats
    probe1_stats=$(echo "$probe1_raw" | grep "min/avg/max" | awk -F'=' '{print $2}' | tr -d ' ms' | awk -F'/' '{print $1,$2,$3,$4}' || echo "0 0 0 0")
    local probe1_loss
    probe1_loss=$(echo "$probe1_raw" | grep -o "[0-9\.]*% packet loss" | awk '{print $1}' || echo "0%")

    read -r p1_min p1_avg p1_max p1_mdev <<< "$probe1_stats"
    printf "Avg RTT: %sms (min: %sms, max: %sms, ±%sms jitter) | Loss: %s\n" "${p1_avg:-0}" "${p1_min:-0}" "${p1_max:-0}" "${p1_mdev:-0}" "$probe1_loss"

    # Probe 2: Hop 2 (Mix-1 -> Exit-1: 172.28.0.21 -> 172.28.0.31)
    echo -n "   [Probe 2] Mix-1   (172.28.0.21) -> Exit-1 (172.28.0.31): "
    local probe2_raw
    probe2_raw=$(docker exec pom-mix-1 ping -c 20 -i 0.1 172.28.0.31 2>&1 || true)
    local probe2_stats
    probe2_stats=$(echo "$probe2_raw" | grep "min/avg/max" | awk -F'=' '{print $2}' | tr -d ' ms' | awk -F'/' '{print $1,$2,$3,$4}' || echo "0 0 0 0")
    local probe2_loss
    probe2_loss=$(echo "$probe2_raw" | grep -o "[0-9\.]*% packet loss" | awk '{print $1}' || echo "0%")

    read -r p2_min p2_avg p2_max p2_mdev <<< "$probe2_stats"
    printf "Avg RTT: %sms (min: %sms, max: %sms, ±%sms jitter) | Loss: %s\n" "${p2_avg:-0}" "${p2_min:-0}" "${p2_max:-0}" "${p2_mdev:-0}" "$probe2_loss"

    # Probe 3: Direct 2-hop cross-layer (Entry-1 -> Exit-1: 172.28.0.11 -> 172.28.0.31)
    echo -n "   [Probe 3] Entry-1 (172.28.0.11) -> Exit-1 (172.28.0.31): "
    local probe3_raw
    probe3_raw=$(docker exec pom-entry-1 ping -c 20 -i 0.1 172.28.0.31 2>&1 || true)
    local probe3_stats
    probe3_stats=$(echo "$probe3_raw" | grep "min/avg/max" | awk -F'=' '{print $2}' | tr -d ' ms' | awk -F'/' '{print $1,$2,$3,$4}' || echo "0 0 0 0")
    local probe3_loss
    probe3_loss=$(echo "$probe3_raw" | grep -o "[0-9\.]*% packet loss" | awk '{print $1}' || echo "0%")

    read -r p3_min p3_avg p3_max p3_mdev <<< "$probe3_stats"
    printf "Avg RTT: %sms (min: %sms, max: %sms, ±%sms jitter) | Loss: %s\n" "${p3_avg:-0}" "${p3_min:-0}" "${p3_max:-0}" "${p3_mdev:-0}" "$probe3_loss"

    # Export structured JSON
    cat <<EOF > /tmp/wan_impairment_verification.json
{
  "profile": "${PROFILE:-custom}",
  "configured_delay": "${DELAY:-none}",
  "configured_jitter": "${JITTER:-none}",
  "configured_loss": "${LOSS:-none}",
  "probe_entry_to_mix": {
    "avg_rtt_ms": "${p1_avg:-0}",
    "jitter_ms": "${p1_mdev:-0}",
    "min_rtt_ms": "${p1_min:-0}",
    "max_rtt_ms": "${p1_max:-0}",
    "loss_rate": "${probe1_loss}"
  },
  "probe_mix_to_exit": {
    "avg_rtt_ms": "${p2_avg:-0}",
    "jitter_ms": "${p2_mdev:-0}",
    "min_rtt_ms": "${p2_min:-0}",
    "max_rtt_ms": "${p2_max:-0}",
    "loss_rate": "${probe2_loss}"
  },
  "probe_entry_to_exit": {
    "avg_rtt_ms": "${p3_avg:-0}",
    "jitter_ms": "${p3_mdev:-0}",
    "min_rtt_ms": "${p3_min:-0}",
    "max_rtt_ms": "${p3_max:-0}",
    "loss_rate": "${probe3_loss}"
  }
}
EOF
    echo ">> Probe verification exported to /tmp/wan_impairment_verification.json"
}

case "$COMMAND" in
    apply)
        apply_impairment
        ;;
    reset)
        reset_impairment
        ;;
    show)
        show_impairment
        ;;
    verify)
        verify_impairment
        ;;
    *)
        usage
        ;;
esac
