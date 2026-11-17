#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Differential Testing Script: Static Rules vs. AI-Only Mode (-A)
Runs the same diverse set of logs through two passes:
  Pass 1: wazuh-local-analysisd (Static Rules enabled) -> records which logs trigger Static Rules (id != 99999)
  Pass 2: wazuh-local-analysisd -A (AI-Only mode)      -> records which logs trigger AI (id == 99999)
Outputs a side-by-side comparison table and summary statistics.
"""

import json
import os
import re
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
ANALYSISD_BIN = REPO_ROOT / "src" / "wazuh-local-analysisd"
AI_DAEMON_SCRIPT = REPO_ROOT / "src" / "daemon" / "ai_daemon.py"
AI_SOCKET = "/var/ossec/queue/ai/ai_inference.sock"
CMP_QUEUE = "/tmp/cmp_rules_vs_ai_queue.sock"
ALERTS_FILE = REPO_ROOT / "logs" / "alerts" / "local_alerts.json"


TEST_CASES = [
    # --- Group A: Classic Rule-Catchable Attacks / Errors ---
    {
        "name": "SSH Invalid User",
        "group": "A_RuleCatchable",
        "expected_malicious": True,
        "location": "/var/log/auth.log",
        "log": "Nov 16 08:00:01 server sshd[12345]: Invalid user admin from 192.168.10.55 port 54321",
    },
    {
        "name": "SSH Failed Password (Hydra)",
        "group": "A_RuleCatchable",
        "expected_malicious": True,
        "location": "/var/log/auth.log",
        "log": "Mar  4 18:25:29 mail sshd[9912]: Failed password for root from 10.10.1.5 port 44122 ssh2",
    },
    {
        "name": "Dovecot IMAP Brute-Force",
        "group": "A_RuleCatchable",
        "expected_malicious": True,
        "location": "/var/log/mail.log",
        "log": "Mar  4 18:25:29 mail dovecot: imap-login: Disconnected (auth failed, 2 attempts in 31 secs): user=<gabriel>, method=PLAIN, rip=192.168.10.50, lip=10.0.0.5",
    },
    {
        "name": "Sudo Authentication Failure",
        "group": "A_RuleCatchable",
        "expected_malicious": True,
        "location": "/var/log/auth.log",
        "log": "Nov 16 08:01:10 server sudo: pam_unix(sudo:auth): authentication failure; logname=www-data uid=33 euid=0 tty=/dev/pts/0 ruser=www-data rhost=  user=root",
    },
    {
        "name": "Apache Nikto Scan",
        "group": "A_RuleCatchable",
        "expected_malicious": True,
        "location": "/var/log/apache2/access.log",
        "log": '192.168.1.99 - - [04/Mar/2020:18:15:10 +0000] "GET /phpmyadmin/scripts/setup.php HTTP/1.1" 404 492 "-" "Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:000001)"',
    },
    {
        "name": "Apache Webshell RCE",
        "group": "A_RuleCatchable",
        "expected_malicious": True,
        "location": "/var/log/apache2/access.log",
        "log": '10.10.1.25 - - [04/Mar/2020:18:22:01 +0000] "GET /uploads/shell.php?cmd=cat%20/etc/passwd HTTP/1.1" 200 1842 "-" "curl/7.68.0"',
    },
    {
        "name": "Apache SQL Injection",
        "group": "A_RuleCatchable",
        "expected_malicious": True,
        "location": "/var/log/apache2/access.log",
        "log": '10.10.1.25 - - [04/Mar/2020:18:23:11 +0000] "GET /index.php?id=1%27%20UNION%20SELECT%201,user(),version()-- HTTP/1.1" 200 3210 "-" "sqlmap/1.4"',
    },
    {
        "name": "Apache Path Traversal",
        "group": "A_RuleCatchable",
        "expected_malicious": True,
        "location": "/var/log/apache2/access.log",
        "log": '10.10.1.25 - - [04/Mar/2020:18:24:05 +0000] "GET /../../../../etc/shadow HTTP/1.1" 403 280 "-" "Mozilla/5.0"',
    },
    {
        "name": "Auditd Webshell Spawned Shell",
        "group": "A_RuleCatchable",
        "expected_malicious": True,
        "location": "/var/log/audit/audit.log",
        "log": 'type=SYSCALL msg=audit(1583346120.123:456): arch=c000003e syscall=59 success=yes exit=0 a0=55a1 a1=55b2 a2=55c3 a3=0 items=2 ppid=1024 pid=2048 auid=4294967295 uid=33 gid=33 euid=33 suid=33 fsuid=33 egid=33 sgid=33 fsgid=33 tty=(none) ses=4294967295 comm="sh" exe="/bin/dash" key=(null)',
    },
    {
        "name": "Dpkg Package Installed (Rule 2902)",
        "group": "A_RuleCatchable",
        "expected_malicious": False,
        "location": "/var/log/dpkg.log",
        "log": "2026-11-16 08:00:10 status installed curl:amd64 8.5.0-2ubuntu10",
    },
    {
        "name": "Windows Sysmon Credential Dumping",
        "group": "A_RuleCatchable",
        "expected_malicious": True,
        "location": "WinEvtLog:Microsoft-Windows-Sysmon/Operational",
        "log": json.dumps({
            "eventName": "Microsoft-Windows-Sysmon/Operational",
            "eventDescription": "Microsoft-Windows-Sysmon",
            "payloadAsUTF": "Process accessed lsass.exe with GrantedAccess 0x1010 from mimikatz.exe",
        }),
    },

    # --- Group B: Obfuscated / Novel Variants (Harder for Static Rules) ---
    {
        "name": "Obfuscated Webshell Base64 POST",
        "group": "B_ObfuscatedVariant",
        "expected_malicious": True,
        "location": "/var/log/apache2/access.log",
        "log": '172.16.0.88 - - [04/Mar/2020:18:29:44 +0000] "POST /assets/cache_88a1.php?x=Y2F0IC9ldGMvcGFzc3dk HTTP/1.1" 200 512 "-" "Python-urllib/3.8"',
    },
    {
        "name": "Hidden PHP Upload in Error Log",
        "group": "B_ObfuscatedVariant",
        "expected_malicious": True,
        "location": "/var/log/apache2/error.log",
        "log": '[Wed Mar 04 18:30:12.100 2020] [php7:notice] [pid 4120] [client 10.10.1.50:51234] PHP Warning:  system() has been disabled for security reasons in /var/www/html/uploads/img_tmp.php on line 3',
    },
    {
        "name": "SMTP VRFY Enumeration",
        "group": "B_ObfuscatedVariant",
        "expected_malicious": True,
        "location": "/var/log/exim4/mainlog",
        "log": "2020-03-04 18:19:11 H=(scanner.local) [192.168.10.55] F=<> rejected RCPT <root@cup.com>: Unknown user",
    },

    # --- Group C: Benign Operational Errors (False Positive Check) ---
    {
        "name": "Benign df -P Output",
        "group": "C_BenignNoise",
        "expected_malicious": False,
        "location": "df -P",
        "log": "ossec: output: 'df -P': none               1956672        36   1956636       1% /mnt/wslg",
    },
    {
        "name": "Benign Journald Warning",
        "group": "C_BenignNoise",
        "expected_malicious": False,
        "location": "journald",
        "log": "Nov 16 08:05:00 Admin wsl-pro-service[7140]: WARNING Exiting after <nil>: check if the Windows agent is installed and running.",
    },
    {
        "name": "Benign Apache 404 favicon",
        "group": "C_BenignNoise",
        "expected_malicious": False,
        "location": "/var/log/apache2/access.log",
        "log": '192.168.1.10 - - [04/Mar/2020:18:12:01 +0000] "GET /favicon.ico HTTP/1.1" 404 491 "http://cup.com/" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:73.0) Gecko/20100101 Firefox/73.0"',
    },
    {
        "name": "Benign Syslog Cronjob",
        "group": "C_BenignNoise",
        "expected_malicious": False,
        "location": "/var/log/syslog",
        "log": "Mar  4 18:17:01 server CRON[14201]: (root) CMD (   cd / && run-parts --report /etc/cron.hourly)",
    },
    {
        "name": "Benign SSH Accepted Publickey",
        "group": "C_BenignNoise",
        "expected_malicious": False,
        "location": "/var/log/auth.log",
        "log": "Mar  4 18:18:02 server sshd[14300]: Accepted publickey for ubuntu from 192.168.1.20 port 51200 ssh2: RSA SHA256:abcdef123456",
    },
]


def is_socket_alive(sock_path: str) -> bool:
    if not os.path.exists(sock_path):
        return False
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(0.5)
    try:
        s.connect(sock_path)
        return True
    except OSError:
        return False
    finally:
        s.close()


def run_pass(ai_only: bool, cases: list) -> list:
    """Run all test cases through wazuh-local-analysisd in either Hybrid or AI-Only mode"""
    ALERTS_FILE.write_text("", encoding="utf-8")
    if os.path.exists(CMP_QUEUE):
        os.unlink(CMP_QUEUE)

    env = os.environ.copy()
    env["LD_LIBRARY_PATH"] = f"{REPO_ROOT / 'src'}:{env.get('LD_LIBRARY_PATH', '')}"

    cmd = [str(ANALYSISD_BIN)]
    if ai_only:
        cmd.append("-A")
    cmd.extend(["-D", str(REPO_ROOT), "-f", "-u", "root", "-g", "root", "-q", CMP_QUEUE])

    proc = subprocess.Popen(cmd, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    results = []

    try:
        for _ in range(450):
            if os.path.exists(CMP_QUEUE):
                break
            time.sleep(0.1)

        if not os.path.exists(CMP_QUEUE):
            raise RuntimeError(f"Failed to start wazuh-local-analysisd (ai_only={ai_only})")

        with open(ALERTS_FILE, "r", encoding="utf-8") as alerts_fp:
            alerts_fp.seek(0, os.SEEK_END)
            for tc in cases:
                wire_msg = f"1:{tc['location']}:{tc['log']}"
                client = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
                try:
                    client.sendto(wire_msg.encode("utf-8", errors="replace"), CMP_QUEUE)
                finally:
                    client.close()

                matched_alerts = []
                deadline = time.time() + 0.45
                while time.time() < deadline:
                    line = alerts_fp.readline()
                    if line:
                        line = line.strip()
                        if line:
                            try:
                                alert = json.loads(line)
                                matched_alerts.append(alert)
                                # If in AI-only mode, 1 alert max per event; in Hybrid mode, static rule fires immediately
                                if ai_only or str(alert.get("rule", {}).get("id")) != "99999":
                                    break
                            except json.JSONDecodeError:
                                pass
                    time.sleep(0.01)

                # Separate static rule alert vs AI alert
                static_alert = next((a for a in matched_alerts if str(a.get("rule", {}).get("id")) != "99999"), None)
                ai_alert = next((a for a in matched_alerts if str(a.get("rule", {}).get("id")) == "99999"), None)
                results.append({"static": static_alert, "ai": ai_alert})

    finally:
        if proc.poll() is None:
            proc.send_signal(signal.SIGTERM)
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        if os.path.exists(CMP_QUEUE):
            os.unlink(CMP_QUEUE)

    return results


def extract_ai_label(ai_alert: dict) -> str:
    if not ai_alert:
        return "-"
    desc = ai_alert.get("rule", {}).get("description", "")
    m = re.search(r"AI Threat Detected:\s*(.+?)\s*\(Confidence:\s*([\d.]+%)\)", desc)
    if m:
        return f"{m.group(1)} ({m.group(2)})"
    return desc[:28]


def main():
    if not ANALYSISD_BIN.exists():
        print(f"[!] Missing {ANALYSISD_BIN}")
        sys.exit(1)

    (REPO_ROOT / "logs" / "alerts").mkdir(parents=True, exist_ok=True)
    started_ai_daemon = None

    try:
        if not is_socket_alive(AI_SOCKET):
            print("[*] Launching ai_daemon.py...")
            started_ai_daemon = subprocess.Popen(
                [sys.executable, str(AI_DAEMON_SCRIPT), "--socket", AI_SOCKET],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            for _ in range(120):
                if is_socket_alive(AI_SOCKET):
                    break
                time.sleep(0.5)
        else:
            print(f"[+] Using active AI Daemon socket: {AI_SOCKET}")

        print("[*] Pass 1: Running Static Rules (Hybrid mode)...")
        pass1 = run_pass(ai_only=False, cases=TEST_CASES)

        print("[*] Pass 2: Running AI-Only mode (-A)...")
        pass2 = run_pass(ai_only=True, cases=TEST_CASES)

        print("\n" + "=" * 115)
        print(f"{'Test Case':<34} | {'Group':<18} | {'Static Rule':<16} | {'AI-Only (-A)':<28} | {'Outcome'}")
        print("-" * 115)

        stats = {
            "both_caught": 0,
            "rule_only": 0,
            "ai_only": 0,
            "neither_caught_attack": 0,
            "benign_ok": 0,
            "rule_fp": 0,
            "ai_fp": 0,
        }

        for tc, p1, p2 in zip(TEST_CASES, pass1, pass2):
            st = p1["static"]
            ai = p2["ai"]

            st_str = f"ID:{st['rule']['id']} L{st['rule']['level']}" if st else "-"
            ai_str = f"L{ai['rule']['level']} {extract_ai_label(ai)}" if ai else "-"

            st_hit = st is not None
            ai_hit = ai is not None

            if tc["expected_malicious"]:
                if st_hit and ai_hit:
                    outcome = "BOTH CAUGHT"
                    stats["both_caught"] += 1
                elif st_hit and not ai_hit:
                    outcome = "RULE ONLY (AI missed)"
                    stats["rule_only"] += 1
                elif not st_hit and ai_hit:
                    outcome = "AI ONLY (Rule missed)"
                    stats["ai_only"] += 1
                else:
                    outcome = "MISSED BY BOTH"
                    stats["neither_caught_attack"] += 1
            else:
                if not st_hit and not ai_hit:
                    outcome = "OK (Benign)"
                    stats["benign_ok"] += 1
                else:
                    fps = []
                    if st_hit:
                        fps.append("Rule")
                        stats["rule_fp"] += 1
                    if ai_hit:
                        fps.append("AI")
                        stats["ai_fp"] += 1
                    outcome = f"ALERT ({'+'.join(fps)})"

            print(f"{tc['name']:<34} | {tc['group']:<18} | {st_str:<16} | {ai_str:<28} | {outcome}")

        print("=" * 115)
        print("SUMMARY:")
        print(f"  Total Attack/Malicious Cases : {sum(1 for t in TEST_CASES if t['expected_malicious'])}")
        print(f"    - Both Rule & AI Caught    : {stats['both_caught']}")
        print(f"    - Rule Only (AI Missed)    : {stats['rule_only']}")
        print(f"    - AI Only (Rule Missed)    : {stats['ai_only']}")
        print(f"    - Missed by Both           : {stats['neither_caught_attack']}")
        print(f"  Total Benign/Noise Cases     : {sum(1 for t in TEST_CASES if not t['expected_malicious'])}")
        print(f"    - Correctly Ignored (OK)   : {stats['benign_ok']}")
        print(f"    - Static Rule Alerts       : {stats['rule_fp']}")
        print(f"    - AI False Positives       : {stats['ai_fp']}")

    finally:
        if started_ai_daemon and started_ai_daemon.poll() is None:
            started_ai_daemon.send_signal(signal.SIGTERM)
            started_ai_daemon.wait(timeout=5)


if __name__ == "__main__":
    main()

