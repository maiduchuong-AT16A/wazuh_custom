import socket
import os
import sys

SOCKET_PATH = "/var/ossec/queue/sockets/alerts_queue"

if os.path.exists(SOCKET_PATH):
    os.remove(SOCKET_PATH)

print(f"Starting simulated wazuh-agentd on {SOCKET_PATH}...")
try:
    server = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    server.bind(SOCKET_PATH)
    # Give everyone permissions to write to this socket
    os.chmod(SOCKET_PATH, 0o777)
except Exception as e:
    print(f"Failed to create socket: {e}")
    sys.exit(1)

print("Listening for forwarded alerts from local-analysisd...")
try:
    while True:
        datagram = server.recv(65536)
        if not datagram:
            break
        print("\n=== [SIMULATED WAZUH-AGENTD] RECEIVED ALERT ON ALERTSQUEUE ===")
        print(datagram.decode('utf-8', errors='replace'))
        print("==============================================================\n")
except KeyboardInterrupt:
    print("\nShutting down simulated wazuh-agentd.")
finally:
    if os.path.exists(SOCKET_PATH):
        os.remove(SOCKET_PATH)
