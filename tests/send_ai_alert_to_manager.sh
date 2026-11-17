#!/usr/bin/env bash
# ==============================================================================
# Script: send_ai_alert_to_manager.sh
# Purpose: Bắn log mẫu vào dịch vụ Wazuh Agent đang chạy để AI phát hiện
#          và đẩy trực tiếp cảnh báo Rule 99999 lên Wazuh Manager qua cổng 1514.
# ==============================================================================

set -e

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="$REPO_ROOT/src/daemon/.venv/bin/python"
REPLAYER="$REPO_ROOT/tests/replay_samples.py"
QUEUE_SOCK="/var/ossec/queue/sockets/queue"
ALERTS_SOCK="/var/ossec/queue/sockets/alerts_queue"
AI_SOCK="/var/ossec/queue/ai/ai_inference.sock"
LOCAL_ALERTS="/var/ossec/logs/alerts/local_alerts.json"

COUNT="${1:-3}"
TYPE="${2:-both}"

echo "=========================================================================="
echo "   KỊCH BẢN BẮN LOG AI PHÁT HIỆN & CHUYỂN TIẾP LÊN WAZUH MANAGER"
echo "=========================================================================="
echo "[*] Số lượng log kiểm thử : $COUNT"
echo "[*] Loại log              : $TYPE (ait: Linux, comiset: Windows, both: cả 2)"
echo ""

# 1. Kiểm tra môi trường Python
if [ ! -x "$PYTHON_BIN" ]; then
    echo "[!] Lỗi: Không tìm thấy Python môi trường ảo tại $PYTHON_BIN"
    echo "    Vui lòng thiết lập .venv trong $REPO_ROOT/src/daemon trước."
    exit 1
fi

# 2. Kiểm tra AI Daemon
if [ ! -S "$AI_SOCK" ]; then
    echo "[!] Cảnh báo: AI Daemon chưa chạy (Không thấy $AI_SOCK)."
    echo "[*] Đang tự động kích hoạt AI Daemon chạy ngầm..."
    nohup "$PYTHON_BIN" "$REPO_ROOT/src/daemon/ai_daemon.py" > /var/ossec/logs/ai_daemon.log 2>&1 &
    
    echo -n "[*] Đang chờ AI Daemon nạp mô hình vào RAM..."
    for i in {1..60}; do
        if [ -S "$AI_SOCK" ]; then
            break
        fi
        sleep 0.5
        echo -n "."
    done
    echo ""
    
    if [ ! -S "$AI_SOCK" ]; then
        echo "[!] Thất bại: Không thể khởi chạy AI Daemon. Xem log tại /var/ossec/logs/ai_daemon.log"
        exit 1
    fi
    echo "[+] AI Daemon đã sẵn sàng!"
else
    echo "[+] AI Daemon đang hoạt động ($AI_SOCK)."
fi

# 3. Kiểm tra Wazuh Agent Service
if [ ! -S "$QUEUE_SOCK" ] || [ ! -S "$ALERTS_SOCK" ]; then
    echo "[!] Cảnh báo: Socket hàng đợi của Wazuh Agent chưa đầy đủ."
    echo "[*] Đang khởi động lại dịch vụ Wazuh Agent..."
    /var/ossec/bin/wazuh-control restart
    sleep 3
fi

if [ ! -S "$QUEUE_SOCK" ]; then
    echo "[!] Lỗi: Không tìm thấy socket tiếp nhận log $QUEUE_SOCK"
    echo "    Hãy chắc chắn lệnh '/var/ossec/bin/wazuh-control status' hiển thị đầy đủ các tiến trình."
    exit 1
fi

echo "[+] Dịch vụ Wazuh Agent đang hoạt động và kết nối sẵn sàng."
echo ""

# Ghi nhận số dòng log hiện tại
BEFORE_COUNT=0
if [ -f "$LOCAL_ALERTS" ]; then
    BEFORE_COUNT=$(wc -l < "$LOCAL_ALERTS")
fi

# 4. Bắn log kiểm thử qua replayer vào socket thật
echo "=========================================================================="
echo ">> BƯỚC 1: Bắn log mẫu chưa có Rule tĩnh vào $QUEUE_SOCK..."
echo "=========================================================================="
"$PYTHON_BIN" "$REPLAYER" --socket "$QUEUE_SOCK" --count "$COUNT" --type "$TYPE"

# 5. Chờ và kiểm tra cảnh báo Rule 99999 sinh ra cục bộ
echo ""
echo "=========================================================================="
echo ">> BƯỚC 2: Kiểm tra kết quả AI phân loại & sinh cảnh báo Rule 99999..."
echo "=========================================================================="
sleep 2

AFTER_COUNT=0
if [ -f "$LOCAL_ALERTS" ]; then
    AFTER_COUNT=$(wc -l < "$LOCAL_ALERTS")
fi

NEW_LINES=$((AFTER_COUNT - BEFORE_COUNT))
echo "[+] Số lượng cảnh báo mới được ghi vào Agent: $NEW_LINES"

# Lọc ra các alert 99999 mới nhất
if [ "$NEW_LINES" -gt 0 ]; then
    echo ""
    echo ">> Cảnh báo AI (Rule 99999) vừa được sinh ra trên Agent:"
    tail -n "$NEW_LINES" "$LOCAL_ALERTS" | grep '"id":"99999"' | while read -r line; do
        DESC=$(echo "$line" | grep -o '"description":"[^"]*"' | cut -d'"' -f4)
        LEVEL=$(echo "$line" | grep -o '"level":[0-9]*' | cut -d':' -f2)
        echo "  [AI ALERT] Level $LEVEL | $DESC"
    done
fi

echo ""
echo "=========================================================================="
echo ">> BƯỚC 3: HƯỚNG DẪN KIỂM TRA TRÊN MÁY WAZUH MANAGER"
echo "=========================================================================="
echo "Các cảnh báo trên ĐÃ ĐƯỢC wazuh-agentd đóng gói và gửi qua mạng về Manager."
echo "Để kiểm chứng trực tiếp, trên máy WAZUH MANAGER hãy gõ lệnh sau:"
echo ""
echo "    tail -f /var/ossec/logs/alerts/alerts.json | grep --line-buffered '\"id\":\"99999\"'"
echo ""
echo "Hoặc xem toàn bộ log cảnh báo mới nhất từ Manager:"
echo "    tail -n 20 /var/ossec/logs/alerts/alerts.json | jq ."
echo "=========================================================================="
