#!/usr/bin/env bash
set -euo pipefail

PAYLOAD_FILE="/home/user/Stardome/stardome-local-python-client_SLIDING/payloads/payload_10B.txt"
PORT="/dev/ttyUSB0"
BAUD="115200"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --payload-file)
      PAYLOAD_FILE="$2"
      shift 2
      ;;
    --port)
      PORT="$2"
      shift 2
      ;;
    --baud)
      BAUD="$2"
      shift 2
      ;;
    *)
      echo "Unknown arg: $1" >&2
      exit 2
      ;;
  esac
done

if [[ ! -f "$PAYLOAD_FILE" ]]; then
  echo "ERROR: payload file not found: $PAYLOAD_FILE" >&2
  exit 2
fi

echo "[gate] Building stardome-client"
make clean && make -j12

echo "[gate] Running attestation (port=$PORT baud=$BAUD payload=$PAYLOAD_FILE)"
./bin/stardome-client \
  --port "$PORT" \
  --baud "$BAUD" \
  attestation \
  --payload-file "$PAYLOAD_FILE" \
  --out-tree stardome_tree.bin \
  --out-attestation stardome_attestation.bin

echo "[gate] Running verify"
./bin/stardome-client verify --tree stardome_tree.bin --attestation stardome_attestation.bin

echo "[gate] PASS: QCBOR attestation+verify merge gate satisfied"
