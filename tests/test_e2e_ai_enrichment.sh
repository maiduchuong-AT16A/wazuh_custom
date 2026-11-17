#!/usr/bin/env bash
set -e

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ANALYSISD_BIN="$REPO_ROOT/src/wazuh-local-analysisd"
TEST_QUEUE="/tmp/test_analysisd_queue.sock"
AI_SOCKET="/var/ossec/queue/ai/ai_inference.sock"
ALERTS_FILE="$REPO_ROOT/logs/alerts/local_alerts.json"
PYTHON_BIN="$REPO_ROOT/src/daemon/.venv/bin/python"

export LD_LIBRARY_PATH="$REPO_ROOT/src:$LD_LIBRARY_PATH"

echo "=== End-to-End AI Enrichment Test ==="

# 1. Reset state
mkdir -p "$REPO_ROOT/logs/alerts"
mkdir -p /var/ossec/queue/ai
rm -f "$AI_SOCKET"
rm -f "$TEST_QUEUE"
> "$ALERTS_FILE"

DAEMON_PID=""
ANALYSISD_PID=""

cleanup() {
    echo "[*] Cleaning up test daemons..."
    if [ -n "$ANALYSISD_PID" ] && kill -0 "$ANALYSISD_PID" 2>/dev/null; then
        kill -15 "$ANALYSISD_PID" 2>/dev/null || true
        wait "$ANALYSISD_PID" 2>/dev/null || true
    fi
    if [ -n "$DAEMON_PID" ] && kill -0 "$DAEMON_PID" 2>/dev/null; then
        kill -15 "$DAEMON_PID" 2>/dev/null || true
        wait "$DAEMON_PID" 2>/dev/null || true
    fi
    rm -f "$AI_SOCKET" "$TEST_QUEUE"
}
trap cleanup EXIT

# 2. Launch AI Daemon
echo "[*] Launching Python AI Daemon..."
"$PYTHON_BIN" "$REPO_ROOT/src/daemon/ai_daemon.py" --socket "$AI_SOCKET" &
DAEMON_PID=$!

for i in {1..120}; do
    if [ -S "$AI_SOCKET" ]; then
        break
    fi
    sleep 0.5
done

if [ ! -S "$AI_SOCKET" ]; then
    echo "[!] Failed: AI Daemon socket $AI_SOCKET not created."
    exit 1
fi
echo "[+] AI Daemon ready and listening on $AI_SOCKET"

# 3. Launch wazuh-local-analysisd
echo "[*] Launching wazuh-local-analysisd..."
cd "$REPO_ROOT"
"$ANALYSISD_BIN" -D "$REPO_ROOT" -f -u root -g root -q "$TEST_QUEUE" &
ANALYSISD_PID=$!

for i in {1..30}; do
    if [ -S "$TEST_QUEUE" ]; then
        break
    fi
    sleep 0.1
done

if [ ! -S "$TEST_QUEUE" ]; then
    echo "[!] Failed: analysisd socket $TEST_QUEUE not created."
    exit 1
fi
echo "[+] wazuh-local-analysisd ready and listening on $TEST_QUEUE"

# 4. Replay samples and verify alerts
echo "[*] Replaying sample logs..."
"$PYTHON_BIN" "$REPO_ROOT/tests/replay_samples.py" --socket "$TEST_QUEUE" --count 5 --type both --verify

# 5. Validate alerts file contents
echo "[*] Checking generated alerts in $ALERTS_FILE..."
if [ ! -s "$ALERTS_FILE" ]; then
    echo "[!] Error: No alerts written to $ALERTS_FILE"
    exit 1
fi

COUNT_AI=$(grep -c '"id":"99999"' "$ALERTS_FILE" || true)
echo "[+] Total AI Alerts with Rule ID 99999: $COUNT_AI"

if [ "$COUNT_AI" -lt 1 ]; then
    echo "[!] Error: Expected at least 1 AI alert with ID 99999, found $COUNT_AI"
    exit 1
fi

echo "Sample generated alert:"
grep '"id":"99999"' "$ALERTS_FILE" | head -n 1

echo "=== End-to-End AI Enrichment Test PASSED ==="
