#!/usr/bin/env bash
# ==============================================================================
# PRISM / POM Mixnet Pre-Cloud Benchmark & Validation Suite
# ==============================================================================
# Orchestrates Mode A (Baseline), Mode B (Constrained), Stepped Soaks,
# Constant-Rate Stability, WAN Impairment Profiles, Failure Recovery,
# and compiles the full 20-section validation report.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_ROOT"

POM_STRESS_BIN="/tmp/cargo_target/release/pom-stress"
TELEMETRY_SCRIPT="$PROJECT_ROOT/scripts/soak_telemetry.py"
WAN_SCRIPT="$PROJECT_ROOT/scripts/network_impairment.sh"
FAIL_SCRIPT="$PROJECT_ROOT/scripts/failure_recovery_test.sh"
REPORT_SCRIPT="$PROJECT_ROOT/scripts/generate_report.py"

COMMAND="${1:-help}"

ensure_binaries() {
    if [[ ! -f "$POM_STRESS_BIN" ]]; then
        echo ">> Building release binaries..."
        cargo build --release --bin pom-stress --bin prism-node
    fi
}

start_telemetry_collector() {
    local dur="${1:-0}"
    local intv="${2:-15.0}"
    rm -f /tmp/soak_stop /tmp/soak_telemetry.csv
    python3 "$TELEMETRY_SCRIPT" collect --csv /tmp/soak_telemetry.csv --interval "$intv" --duration "$dur" > /tmp/soak_collector.log 2>&1 &
    TELEMETRY_PID=$!
    echo ">> Background telemetry collector started (PID $TELEMETRY_PID, interval ${intv}s)"
}

stop_telemetry_collector() {
    touch /tmp/soak_stop
    if [[ -n "${TELEMETRY_PID:-}" ]]; then
        kill -TERM "$TELEMETRY_PID" 2>/dev/null || true
        wait "$TELEMETRY_PID" 2>/dev/null || true
    fi
    echo ">> Background telemetry collector stopped. Running time-series regression analysis..."
    python3 "$TELEMETRY_SCRIPT" analyze --csv /tmp/soak_telemetry.csv --json /tmp/soak_analysis.json
}

setup_mode_a() {
    echo ">> Configuring Mode A (Unconstrained Baseline Host Execution)..."
    docker compose down >/dev/null 2>&1 || true
    docker compose up -d
    sleep 2
    $WAN_SCRIPT reset >/dev/null 2>&1 || true
    echo ">> Mode A active: Full host resources, 0% artificial delay."
}

setup_mode_b() {
    echo ">> Configuring Mode B (Resource-Constrained: 0.50 CPU, 64 MiB RAM per relay)..."
    docker compose -f docker-compose.yml -f docker-compose.constrained.yml down >/dev/null 2>&1 || true
    docker compose -f docker-compose.yml -f docker-compose.constrained.yml up -d
    sleep 2
    $WAN_SCRIPT reset >/dev/null 2>&1 || true
    echo ">> Mode B active: cgroups cpu quota=50000 (0.50 cores), mem_limit=64M."
}

cmd_baseline() {
    echo "================================================================================"
    echo "       POM MIXNET VALIDATION: MODE A UNCONSTRAINED BASELINE BENCHMARK           "
    echo "================================================================================"
    ensure_binaries
    setup_mode_a
    $WAN_SCRIPT verify

    start_telemetry_collector 45 5.0
    $POM_STRESS_BIN -d 30 -r 2000 -c 16 -b 8 --csv-out /tmp/pom_stress_timeseries.csv
    stop_telemetry_collector

    python3 "$REPORT_SCRIPT" --mode "Mode A (Unconstrained Baseline)" --wan "Clean (Line Rate)" --output /tmp/pom_benchmark_report.md
    echo ">> Baseline evaluation complete -> /tmp/pom_benchmark_report.md"
}

cmd_constrained() {
    echo "================================================================================"
    echo "       POM MIXNET VALIDATION: MODE B RESOURCE-CONSTRAINED BENCHMARK             "
    echo "================================================================================"
    ensure_binaries
    setup_mode_b
    $WAN_SCRIPT verify

    start_telemetry_collector 45 5.0
    $POM_STRESS_BIN -d 30 -r 1500 -c 16 -b 8 --csv-out /tmp/pom_stress_timeseries.csv
    stop_telemetry_collector

    python3 "$REPORT_SCRIPT" --mode "Mode B (Resource-Constrained)" --wan "Clean (Line Rate)" --output /tmp/pom_benchmark_report.md
    echo ">> Constrained evaluation complete -> /tmp/pom_benchmark_report.md"
}

cmd_stepped_soak() {
    local scale="${2:-1}" # 1 for full 36m (2160s), or fractional e.g. 0.05 for fast 108s test
    echo "================================================================================"
    echo "       POM MIXNET VALIDATION: TEST A STEPPED SOAK BENCHMARK                     "
    echo "================================================================================"
    ensure_binaries
    setup_mode_a

    # Standard stages: 500:600s, 1000:720s, 1800:600s, 250:240s
    local s1
    local s2
    local s3
    local s4
    s1=$(awk "BEGIN {print int(600 * $scale + 0.5)}")
    s2=$(awk "BEGIN {print int(720 * $scale + 0.5)}")
    s3=$(awk "BEGIN {print int(600 * $scale + 0.5)}")
    s4=$(awk "BEGIN {print int(240 * $scale + 0.5)}")
    s1=$(( s1 < 10 ? 10 : s1 ))
    s2=$(( s2 < 12 ? 12 : s2 ))
    s3=$(( s3 < 10 ? 10 : s3 ))
    s4=$(( s4 < 5 ? 5 : s4 ))
    local total=$(( s1 + s2 + s3 + s4 ))

    local stage_spec="500:${s1},1000:${s2},1800:${s3},250:${s4}"
    echo ">> Running Stepped Soak Profile: $stage_spec (Total duration: ${total}s)"

    start_telemetry_collector $(( total + 10 )) 5.0
    $POM_STRESS_BIN --stages "$stage_spec" -c 16 -b 8 --csv-out /tmp/pom_stress_timeseries.csv
    stop_telemetry_collector

    python3 "$REPORT_SCRIPT" --mode "Test A (Stepped Soak)" --wan "Clean (Line Rate)" --output /tmp/pom_benchmark_report.md
    echo ">> Stepped soak evaluation complete -> /tmp/pom_benchmark_report.md"
}

cmd_constant_soak() {
    local rate="${2:-1000}"
    local duration="${3:-1800}"
    echo "================================================================================"
    echo "   POM MIXNET VALIDATION: TEST B CONSTANT-RATE STABILITY BENCHMARK (${rate} pps) "
    echo "================================================================================"
    ensure_binaries
    setup_mode_a

    start_telemetry_collector $(( duration + 10 )) 15.0
    $POM_STRESS_BIN -d "$duration" -r "$rate" -c 16 -b 8 --csv-out /tmp/pom_stress_timeseries.csv
    stop_telemetry_collector

    python3 "$REPORT_SCRIPT" --mode "Test B (Constant Rate: ${rate} pps)" --wan "Clean (Line Rate)" --output /tmp/pom_benchmark_report.md
    echo ">> Constant soak evaluation complete -> /tmp/pom_benchmark_report.md"
}

cmd_wan_profile_a() {
    echo "================================================================================"
    echo "       POM MIXNET VALIDATION: WAN PROFILE A (15ms ± 3ms, 0.5% Loss)             "
    echo "================================================================================"
    ensure_binaries
    setup_mode_a
    $WAN_SCRIPT apply --profile A
    $WAN_SCRIPT verify

    start_telemetry_collector 45 5.0
    $POM_STRESS_BIN -d 30 -r 1000 -c 16 -b 8 --csv-out /tmp/pom_stress_timeseries.csv
    stop_telemetry_collector
    $WAN_SCRIPT reset

    python3 "$REPORT_SCRIPT" --mode "Mode A (Baseline)" --wan "Profile A (15ms ± 3ms, 0.5% Loss)" --output /tmp/pom_benchmark_report.md
    echo ">> WAN Profile A evaluation complete -> /tmp/pom_benchmark_report.md"
}

cmd_wan_profile_b() {
    echo "================================================================================"
    echo "       POM MIXNET VALIDATION: WAN PROFILE B (50ms ± 10ms, 1.0% Loss)            "
    echo "================================================================================"
    ensure_binaries
    setup_mode_a
    $WAN_SCRIPT apply --profile B
    $WAN_SCRIPT verify

    start_telemetry_collector 45 5.0
    $POM_STRESS_BIN -d 30 -r 1000 -c 16 -b 8 --csv-out /tmp/pom_stress_timeseries.csv
    stop_telemetry_collector
    $WAN_SCRIPT reset

    python3 "$REPORT_SCRIPT" --mode "Mode A (Baseline)" --wan "Profile B (50ms ± 10ms, 1.0% Loss)" --output /tmp/pom_benchmark_report.md
    echo ">> WAN Profile B evaluation complete -> /tmp/pom_benchmark_report.md"
}

cmd_failure_recovery() {
    ensure_binaries
    setup_mode_a
    $FAIL_SCRIPT
    python3 "$REPORT_SCRIPT" --mode "Fault Tolerance & Recovery" --wan "Dynamic Injection" --output /tmp/pom_benchmark_report.md
}

cmd_report() {
    python3 "$REPORT_SCRIPT" --output /tmp/pom_benchmark_report.md
}

cmd_full_run() {
    echo "================================================================================"
    echo "       PRISM / POM MIXNET: FULL PRE-CLOUD VALIDATION SUITE RUN                  "
    echo "================================================================================"
    ensure_binaries

    echo "\n>>> Phase 1/5: Mode A Unconstrained Baseline..."
    cmd_baseline

    echo "\n>>> Phase 2/5: Mode B Resource-Constrained..."
    cmd_constrained

    echo "\n>>> Phase 3/5: WAN Profile A Impairment Resiliency..."
    cmd_wan_profile_a

    echo "\n>>> Phase 4/5: Controlled Failure-Recovery..."
    cmd_failure_recovery

    echo "\n>>> Phase 5/5: Final 20-Section Validation Report..."
    python3 "$REPORT_SCRIPT" --mode "Full Pre-Cloud Multi-Mode Validation" --wan "Empirical Profile Matrix" --output "$PROJECT_ROOT/POM_PRECLOUD_VALIDATION_REPORT.md"

    echo "================================================================================"
    echo ">> FULL VALIDATION SUITE COMPLETE!"
    echo ">> Comprehensive Report generated at: $PROJECT_ROOT/POM_PRECLOUD_VALIDATION_REPORT.md"
    echo "================================================================================"
}

case "$COMMAND" in
    baseline)
        cmd_baseline
        ;;
    constrained)
        cmd_constrained
        ;;
    stepped-soak)
        cmd_stepped_soak "$@"
        ;;
    constant-soak)
        cmd_constant_soak "$@"
        ;;
    wan-profile-a)
        cmd_wan_profile_a
        ;;
    wan-profile-b)
        cmd_wan_profile_b
        ;;
    failure-recovery)
        cmd_failure_recovery
        ;;
    report)
        cmd_report
        ;;
    full-run)
        cmd_full_run
        ;;
    *)
        cat <<EOF
Usage: $0 <subcommand> [args]

Subcommands:
  baseline            Run Mode A unconstrained baseline test (30s)
  constrained         Run Mode B resource-constrained test (30s, 0.5 CPU, 64M RAM)
  stepped-soak [sc]   Run Test A stepped soak (scale 1=36m, 0.05=108s fast)
  constant-soak [r] [d] Run Test B constant-rate stability test (rate, duration)
  wan-profile-a       Run WAN Profile A test (15ms ± 3ms, 0.5% drop)
  wan-profile-b       Run WAN Profile B test (50ms ± 10ms, 1.0% drop)
  failure-recovery    Run controlled relay outage and drop recovery test
  report              Recompile 20-section report from existing metrics
  full-run            Execute complete validation suite and generate final report

EOF
        ;;
esac
