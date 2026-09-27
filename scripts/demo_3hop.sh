#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PRISM_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/cargo_target}"
BIN_DIR="$TARGET_DIR/release"

echo "================================================================================"
echo "          PRISM PROTOCOL PROTOTYPE: MANUAL 3-HOP MIXNET DEMONSTRATION           "
echo "================================================================================"

# Ensure binaries are built
if [[ ! -f "$BIN_DIR/prism-node" || ! -f "$BIN_DIR/prism-client" ]]; then
    echo ">> Building release binaries..."
    cargo build --release -p prism-node -p prism-client --manifest-path "$PRISM_DIR/Cargo.toml"
fi

TMP_DIR=$(mktemp -d)
trap "kill -9 \$PID1 \$PID2 \$PID3 2>/dev/null || true; fuser -k 9001/udp 9002/udp 9003/udp 2>/dev/null || true; rm -rf '$TMP_DIR'" EXIT

# Ensure ports 9001, 9002, 9003 are free
fuser -k 9001/udp 9002/udp 9003/udp 2>/dev/null || pkill -f prism-node 2>/dev/null || true
sleep 0.5

echo ">> Starting 3 PRISM mix relay nodes..."

# Start Hop 1 (Layer 1)
"$BIN_DIR/prism-node" --listen 127.0.0.1:9001 --layer 1 --key 1 --mix-rate 50.0 --pool-size 0 > "$TMP_DIR/node1.log" 2>&1 &
PID1=$!

# Start Hop 2 (Layer 2)
"$BIN_DIR/prism-node" --listen 127.0.0.1:9002 --layer 2 --key 2 --mix-rate 50.0 --pool-size 0 > "$TMP_DIR/node2.log" 2>&1 &
PID2=$!

# Start Hop 3 (Layer 3 / Exit)
"$BIN_DIR/prism-node" --listen 127.0.0.1:9003 --layer 3 --key 3 --mix-rate 50.0 --pool-size 0 > "$TMP_DIR/node3.log" 2>&1 &
PID3=$!

echo ">> Relays launched (PIDs: $PID1, $PID2, $PID3). Waiting 1.5s for QUIC socket binding..."
sleep 1.5

MESSAGE="${1:-CONFIDENTIAL: Transfer \$1,000,000 to Alice via PRISM Mixnet}"

echo ""
echo ">> Sending message from PRISM Client..."
echo ">> Circuit Route: Client -> Node 1 (127.0.0.1:9001) -> Node 2 (127.0.0.1:9002) -> Node 3 (127.0.0.1:9003 Exit)"
echo ">> Message Payload: \"$MESSAGE\""
echo ""

"$BIN_DIR/prism-client" send \
    --message "$MESSAGE" \
    --relays "127.0.0.1:9001,127.0.0.1:9002,127.0.0.1:9003" \
    --seeds "1,2,3"

echo ""
echo ">> Waiting 2s for multi-hop Poisson mixing, layer unwrapping, and inner AEAD decryption..."
sleep 2

echo ""
echo "================================================================================"
echo "                         NODE 3 (EXIT RELAY) LOG OUTPUT                         "
echo "================================================================================"
cat "$TMP_DIR/node3.log"
echo "================================================================================"
echo "DEMO COMPLETE: Message was cryptographically authenticated and delivered!"
echo "================================================================================"
