import os
import json
import socket
import time
import unittest
import yaml

SOCKET_PATH = "/var/ossec/queue/sockets/queue"
ALERTS_PATH = "/var/ossec/logs/alerts/local_alerts.json"

def get_cases():
    cases_file = os.path.join(os.path.dirname(__file__), "data", "test_cases", "cases_syscheck_events.yaml")
    with open(cases_file, "r") as f:
        data = yaml.safe_load(f)
    return data

class TestSyscheckConfigurations(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Clear local_alerts.json before running tests
        if os.path.exists(ALERTS_PATH):
            os.remove(ALERTS_PATH)
        time.sleep(0.5)

    def test_syscheckd_cases(self):
        cases = get_cases()
        for case in cases:
            with self.subTest(case=case["name"]):
                input_str = case["input"]
                expected = case["expected"]
                
                # 1. Send the input to wazuh-local-analysisd via socket
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
                try:
                    sock.sendto(input_str.encode("utf-8"), SOCKET_PATH)
                except Exception as e:
                    self.fail(f"Could not send data to socket: {e}")
                finally:
                    sock.close()
                    
                # Wait for the daemon to process and write the alert
                time.sleep(1)
                
                # 2. Read the latest alert from the local_alerts.json file
                if not os.path.exists(ALERTS_PATH):
                    self.fail(f"Alerts file {ALERTS_PATH} was not created!")
                    
                found_alert = False
                with open(ALERTS_PATH, "r") as f:
                    lines = f.readlines()
                    for line in reversed(lines):
                        try:
                            alert = json.loads(line)
                            rule = alert.get("rule", {})
                            
                            # We check if this alert matches our expected rule
                            if str(rule.get("id")) == str(expected["rule_id"]):
                                self.assertEqual(int(rule.get("level")), expected["level"])
                                found_alert = True
                                break
                        except json.JSONDecodeError:
                            continue
                            
                self.assertTrue(found_alert, f"Test '{case['name']}': Expected rule_id {expected['rule_id']} but it was not found in alerts.")

if __name__ == '__main__':
    unittest.main()
