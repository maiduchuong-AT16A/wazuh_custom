import os
import socket
import time
import subprocess

socket_path = "/var/ossec/queue/sockets/queue"
log_path = "/var/ossec/logs/ossec.log"
alerts_path = "/var/ossec/logs/alerts/local_alerts.json"

print("--- Testing production wazuh-local-analysisd socket ---")

# Check if socket exists
if not os.path.exists(socket_path):
    print(f"Error: socket path {socket_path} does not exist!")
    exit(1)

# Send DGRAM packets
try:
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    # Case 1: Trigger Rule 100001 (logcollector)
    msg1 = b"9:logcollector:this is a test_local_alert log line"
    sock.sendto(msg1, socket_path)
    print("Message 1 (Rule 100001) sent successfully.")

    # Case 2: Trigger Rule 100002 (syscheck)
    msg2 = b"9:syscheck:file modified: /var/ossec/etc/important.txt"
    sock.sendto(msg2, socket_path)
    print("Message 2 (Rule 100002) sent successfully.")

    sock.close()
except Exception as e:
    print(f"Error sending message: {e}")
    exit(1)

time.sleep(1)

# Check ossec.log
print("\n--- Recent ossec.log entries ---")
if os.path.exists(log_path):
    with open(log_path, "r") as f:
        lines = f.readlines()
        for line in lines[-20:]:
            if "local-analysisd" in line:
                print(line.strip())
else:
    print(f"Log file {log_path} not found.")

# Check alerts file
print("\n--- Recent alerts ---")
if os.path.exists(alerts_path):
    with open(alerts_path, "r") as f:
        lines = f.readlines()
        for line in lines[-10:]:
            print(line.strip())
else:
    print(f"Alerts file {alerts_path} does not exist.")
