import socket
import time
import sys

def trigger_active_response():
    # Đường dẫn tới socket nhận log của Wazuh (Local Analysisd)
    socket_path = "/var/ossec/queue/sockets/queue"
    
    # Địa chỉ IP giả lập của kẻ tấn công mà ta muốn firewall chặn
    attacker_ip = "192.168.99.101"
    
    try:
        # Tạo Unix Domain Socket (Datagram) - chuẩn giao tiếp của Wazuh
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    except socket.error as e:
        print(f"Lỗi tạo socket: {e}")
        sys.exit(1)

    print(f"[*] Bắt đầu giả lập tấn công Brute-force SSH từ IP {attacker_ip}...")
    
    # Để kích hoạt được firewall-drop, ta cần một cảnh báo Level >= 10 hoặc thuộc group sshd/web/attack.
    # Trong Wazuh, Rule 5710 (SSHD: đăng nhập sai) là Level 5.
    # Khi Rule 5710 xảy ra 8 lần liên tiếp, nó sẽ kích hoạt Rule 5712 (SSHD: Brute force) có Level 10.
    
    for i in range(1, 9):
        # Định dạng gói tin: <MQ>:<decoder_name>:<log_message>
        # '1' là mã cấu hình cho syslog/localfile
        log_msg = f"1:sshd:Jul 02 10:00:{i:02d} server sshd[123]: Failed password for invalid user admin from {attacker_ip} port 2222 ssh2"
        
        try:
            sock.sendto(log_msg.encode('utf-8'), socket_path)
            print(f"  -> Đã gửi log {i}/8: Đăng nhập thất bại từ {attacker_ip}")
            time.sleep(0.1) # Độ trễ nhỏ giữa các lần gửi
        except Exception as e:
            print(f"[!] Lỗi khi gửi dữ liệu vào socket: {e}")
            sys.exit(1)
            
    print(f"\n[*] Đã hoàn tất gửi log giả lập.")
    print("[*] wazuh-local-analysisd sẽ bắt sự kiện này, nâng lên Rule 5712 (Level 10).")
    print("[*] Vì thỏa mãn điều kiện level >= 10 và group sshd, nó sẽ tự động gửi lệnh kích hoạt 'firewall-drop' cho IP trên.")
    
    sock.close()

if __name__ == "__main__":
    trigger_active_response()
