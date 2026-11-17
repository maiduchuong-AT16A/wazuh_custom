# -*- coding: utf-8 -*-
"""
Independent test script validating ModelService and AIDaemon IPC socket
using sample logs from models-AI/samples/ait_sample.xlsx and comiset_sample.xlsx
"""

import os
import sys
import json
import time
import socket
import unittest
import threading
import pandas as pd
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent.parent
sys.path.insert(0, str(BASE_DIR))

from model_service import ModelService
from ai_daemon import AIDaemon


class TestAIDaemon(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ait_model_dir = str(PROJECT_ROOT / "models-AI" / "models" / "ait")
        cls.comiset_model_dir = str(PROJECT_ROOT / "models-AI" / "models" / "comiset")
        cls.ait_sample_file = str(PROJECT_ROOT / "models-AI" / "samples" / "ait_sample.xlsx")
        cls.comiset_sample_file = str(PROJECT_ROOT / "models-AI" / "samples" / "comiset_sample.xlsx")
        cls.test_socket = str(BASE_DIR / "test_ai_inference.sock")

        print("\n=== Initializing ModelService for testing ===")
        cls.service = ModelService(
            ait_model_dir=cls.ait_model_dir,
            comiset_model_dir=cls.comiset_model_dir,
            device="cpu"
        )

    def test_01_ait_sample_inference(self):
        """Test inference on rows from ait_sample.xlsx"""
        print("\n--- Testing AIT (Linux) Samples ---")
        self.assertTrue(os.path.exists(self.ait_sample_file), f"Missing {self.ait_sample_file}")
        df = pd.read_excel(self.ait_sample_file)
        self.assertGreater(len(df), 0, "ait_sample.xlsx should not be empty")

        for idx, row in df.head(5).iterrows():
            event_id = f"test-ait-{idx}"
            # Format row as json string
            row_dict = {k: str(v) for k, v in row.items() if pd.notna(v)}
            log_content = json.dumps(row_dict)

            result = self.service.classify_event(
                event_id=event_id,
                os_type="Linux",
                log_content=log_content
            )

            print(f"Sample {idx} -> is_malicious: {result['is_malicious']}, attack_type: '{result['attack_type']}', conf: {result['confidence_score']:.4f}")
            self.assertEqual(result["event_id"], event_id)
            self.assertIsInstance(result["is_malicious"], bool)
            self.assertIsInstance(result["attack_type"], str)
            self.assertGreaterEqual(result["confidence_score"], 0.0)
            self.assertLessEqual(result["confidence_score"], 1.0)
            self.assertIsNone(result["error"])

    def test_02_comiset_sample_inference(self):
        """Test inference on rows from comiset_sample.xlsx"""
        print("\n--- Testing COMISET (Windows) Samples ---")
        self.assertTrue(os.path.exists(self.comiset_sample_file), f"Missing {self.comiset_sample_file}")
        df = pd.read_excel(self.comiset_sample_file)
        self.assertGreater(len(df), 0, "comiset_sample.xlsx should not be empty")

        for idx, row in df.head(5).iterrows():
            event_id = f"test-comiset-{idx}"
            row_dict = {k: str(v) for k, v in row.items() if pd.notna(v)}
            log_content = json.dumps(row_dict)

            result = self.service.classify_event(
                event_id=event_id,
                os_type="Windows",
                log_content=log_content
            )

            print(f"Sample {idx} -> is_malicious: {result['is_malicious']}, attack_type: '{result['attack_type']}', conf: {result['confidence_score']:.4f}")
            self.assertEqual(result["event_id"], event_id)
            self.assertIsInstance(result["is_malicious"], bool)
            self.assertIsInstance(result["attack_type"], str)
            self.assertGreaterEqual(result["confidence_score"], 0.0)
            self.assertLessEqual(result["confidence_score"], 1.0)
            self.assertIsNone(result["error"])

    def test_03_unix_socket_ipc(self):
        """Test end-to-end Unix Domain Socket communication with AIDaemon"""
        print("\n--- Testing Unix Domain Socket IPC ---")
        import asyncio

        daemon = AIDaemon(
            socket_path=self.test_socket,
            ait_model_dir=self.ait_model_dir,
            comiset_model_dir=self.comiset_model_dir,
            device="cpu",
            model_service=self.service
        )


        def run_daemon():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                loop.run_until_complete(daemon.start())
            except Exception:
                pass
            finally:
                daemon.cleanup()
                loop.close()

        thread = threading.Thread(target=run_daemon, daemon=True)
        thread.start()

        # Wait for socket to become available
        for _ in range(60):
            if os.path.exists(self.test_socket):
                break
            time.sleep(0.1)


        self.assertTrue(os.path.exists(self.test_socket), "Socket file was not created by daemon")

        # Connect via Unix Domain Socket client
        client_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client_sock.settimeout(2.0)
        client_sock.connect(self.test_socket)

        test_payload = {
            "event_id": "sock-test-uuid-001",
            "os_type": "Linux",
            "log_content": "eventName: nmap scan | payloadAsUTF: GET /admin HTTP/1.1"
        }
        client_sock.sendall((json.dumps(test_payload) + "\n").encode("utf-8"))

        response_data = b""
        while not response_data.endswith(b"\n"):
            chunk = client_sock.recv(1024)
            if not chunk:
                break
            response_data += chunk

        client_sock.close()

        resp = json.loads(response_data.decode("utf-8"))
        print(f"Socket Response: {resp}")
        self.assertEqual(resp["event_id"], "sock-test-uuid-001")
        self.assertIn("is_malicious", resp)
        self.assertIn("confidence_score", resp)
        self.assertIsNone(resp.get("error"))

        daemon.cleanup()
        print("Unix Domain Socket IPC test passed successfully!")


if __name__ == "__main__":
    unittest.main()
