#!/usr/bin/env bash
set -e

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ANALYSISD_BIN="$REPO_ROOT/src/wazuh-local-analysisd"
TEST_QUEUE="/tmp/test_fallback_queue.sock"
AI_SOCKET="/var/ossec/queue/ai/ai_inference.sock"

export LD_LIBRARY_PATH="$REPO_ROOT/src:$LD_LIBRARY_PATH"

echo "=== Testing AI Fallback Mechanism ==="


# 1. Ensure AI daemon socket does not exist or daemon is stopped
rm -f "$AI_SOCKET"
rm -f "$TEST_QUEUE"

# 2. Start wazuh-local-analysisd in foreground/background mode with custom test queue
echo "[*] Launching wazuh-local-analysisd on $TEST_QUEUE (with AI Daemon STOPPED)..."
cd "$REPO_ROOT"
"$ANALYSISD_BIN" -D "$REPO_ROOT" -f -u root -g root -q "$TEST_QUEUE" &
ANALYSISD_PID=$!


cleanup() {
    echo "[*] Cleaning up test processes..."
    if [ -n "$ANALYSISD_PID" ] && kill -0 "$ANALYSISD_PID" 2>/dev/null; then
        kill -15 "$ANALYSISD_PID" 2>/dev/null || true
        wait "$ANALYSISD_PID" 2>/dev/null || true
    fi
    rm -f "$TEST_QUEUE"
}
trap cleanup EXIT

# Wait for queue socket to appear
for i in {1..30}; do
    if [ -S "$TEST_QUEUE" ]; then
        break
    fi
    sleep 0.1
done

if [ ! -S "$TEST_QUEUE" ]; then
    echo "[!] Failed: analysisd socket $TEST_QUEUE was not created."
    exit 1
fi

echo "[+] wazuh-local-analysisd is running (PID: $ANALYSISD_PID) and listening on $TEST_QUEUE"

# 3. Send test events through replayer
echo "[*] Sending events with AI Daemon offline..."
"$REPO_ROOT/src/daemon/.venv/bin/python" "$REPO_ROOT/tests/replay_samples.py" --socket "$TEST_QUEUE" --count 3 --type both

# 4. Check if wazuh-local-analysisd is still alive and responsive
sleep 1
if kill -0 "$ANALYSISD_PID" 2>/dev/null; then
    echo "[+] SUCCESS: wazuh-local-analysisd survived all events without AI daemon (no block, no crash)!"
else
    echo "[!] FAILURE: wazuh-local-analysisd terminated unexpectedly!"
    exit 1
fi

echo "=== AI Fallback Test PASSED ==="
