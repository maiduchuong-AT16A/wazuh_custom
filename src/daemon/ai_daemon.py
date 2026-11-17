# -*- coding: utf-8 -*-
"""
AI Inference Daemon for Wazuh Custom
Listens on Unix Domain Socket at /var/ossec/queue/ai/ai_inference.sock
Receives JSON event requests and responds with ML threat classifications.
"""

import os
import sys
import json
import signal
import asyncio
import logging
import argparse
from pathlib import Path

# Add current and parent directories to sys.path
BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent.parent
sys.path.insert(0, str(BASE_DIR))

from model_service import ModelService

DEFAULT_SOCKET_PATH = "/var/ossec/queue/ai/ai_inference.sock"
FALLBACK_SOCKET_PATH = str(BASE_DIR / "ai_inference.sock")

def resolve_model_dir(model_name: str) -> str:
    candidates = [
        BASE_DIR / "models-AI" / "models" / model_name,
        BASE_DIR / "models" / model_name,
        PROJECT_ROOT / "models-AI" / "models" / model_name,
        Path("/var/ossec/ai_daemon/models-AI/models") / model_name,
        Path("/var/ossec/ai_daemon/models") / model_name,
    ]
    if model_name == "ait":
        candidates.append(PROJECT_ROOT / "ait_attack_detector_Linux" / "ait_attack_detector" / "models")
    for c in candidates:
        if c.exists() and ((c / "tfbig.pt").exists() or (c / "metadata.json").exists()):
            return str(c)
    return str(PROJECT_ROOT / "models-AI" / "models" / model_name)

DEFAULT_AIT_MODEL_DIR = resolve_model_dir("ait")
DEFAULT_COMISET_MODEL_DIR = resolve_model_dir("comiset")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [ai-daemon] %(message)s"
)
logger = logging.getLogger("ai_daemon")


class AIDaemon:
    def __init__(self, socket_path: str, ait_model_dir: str = DEFAULT_AIT_MODEL_DIR, comiset_model_dir: str = DEFAULT_COMISET_MODEL_DIR, device: str = "cpu", model_service: ModelService = None):
        self.socket_path = socket_path
        self.ait_model_dir = ait_model_dir
        self.comiset_model_dir = comiset_model_dir
        self.device = device
        self.model_service = model_service
        self.server: asyncio.AbstractServer = None
        self._running = False

    def initialize_models(self):
        if self.model_service is None:
            logger.info(f"Loading AI models from:\n - ait: {self.ait_model_dir}\n - comiset: {self.comiset_model_dir}")
            self.model_service = ModelService(
                ait_model_dir=self.ait_model_dir,
                comiset_model_dir=self.comiset_model_dir,
                device=self.device
            )
            logger.info("AI models initialized successfully.")


    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle incoming client connections from Wazuh C agent"""
        try:
            while not reader.at_eof():
                # Read up to 4096 bytes (MAX_REQUEST_SIZE) or newline-delimited line
                line = await reader.readline()
                if not line:
                    break

                try:
                    payload = line.decode("utf-8", errors="replace").strip()
                    if not payload:
                        continue

                    req = json.loads(payload)
                    event_id = req.get("event_id", "")
                    os_type = req.get("os_type", "Linux")
                    location = req.get("location", "")
                    log_content = req.get("log_content", "")

                    # Classify event using ModelService
                    result = self.model_service.classify_event(
                        event_id=event_id,
                        os_type=os_type,
                        log_content=log_content,
                        location=location
                    )

                    response_bytes = (json.dumps(result) + "\n").encode("utf-8")
                    writer.write(response_bytes)
                    await writer.drain()

                except (ConnectionResetError, BrokenPipeError):
                    logger.debug(f"Client disconnected before response could be sent for {event_id}")
                    break
                except json.JSONDecodeError as jde:
                    logger.warning(f"Invalid JSON received: {jde}")
                    err_resp = {
                        "event_id": "",
                        "is_malicious": False,
                        "attack_type": "",
                        "confidence_score": 0.0,
                        "error": f"Invalid JSON request: {str(jde)}"
                    }
                    try:
                        writer.write((json.dumps(err_resp) + "\n").encode("utf-8"))
                        await writer.drain()
                    except (ConnectionResetError, BrokenPipeError):
                        break
                except Exception as e:
                    logger.exception(f"Error processing request: {e}")
                    err_resp = {
                        "event_id": "",
                        "is_malicious": False,
                        "attack_type": "",
                        "confidence_score": 0.0,
                        "error": str(e)
                    }
                    try:
                        writer.write((json.dumps(err_resp) + "\n").encode("utf-8"))
                        await writer.drain()
                    except (ConnectionResetError, BrokenPipeError):
                        break

        except asyncio.CancelledError:
            pass
        except (ConnectionResetError, BrokenPipeError):
            pass
        except Exception as e:
            logger.warning(f"Client connection closed with error: {e}")

        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    def prepare_socket(self):
        """Ensure socket directory exists and remove existing stale socket file"""
        socket_dir = os.path.dirname(self.socket_path)
        if socket_dir:
            try:
                os.makedirs(socket_dir, mode=0o775, exist_ok=True)
            except PermissionError:
                logger.warning(f"Permission denied creating {socket_dir}. Falling back to {FALLBACK_SOCKET_PATH}")
                self.socket_path = FALLBACK_SOCKET_PATH
                socket_dir = os.path.dirname(self.socket_path)
                os.makedirs(socket_dir, mode=0o775, exist_ok=True)

        if os.path.exists(self.socket_path):
            try:
                os.unlink(self.socket_path)
                logger.info(f"Removed stale socket file at {self.socket_path}")
            except OSError as e:
                logger.error(f"Failed to remove stale socket {self.socket_path}: {e}")

    async def start(self):
        self.prepare_socket()
        self.initialize_models()

        self.server = await asyncio.start_unix_server(
            self.handle_client,
            path=self.socket_path
        )

        # Set permissions on socket file so Wazuh analysisd can read/write
        try:
            os.chmod(self.socket_path, 0o666)
        except OSError as e:
            logger.warning(f"Could not set socket permissions 0666 on {self.socket_path}: {e}")

        self._running = True
        logger.info(f"AI Daemon listening on Unix domain socket: {self.socket_path}")

        async with self.server:
            await self.server.serve_forever()

    def cleanup(self):
        """Cleanup socket file on exit"""
        logger.info("Cleaning up AI Daemon resources...")
        if os.path.exists(self.socket_path):
            try:
                os.unlink(self.socket_path)
                logger.info(f"Unlinked socket {self.socket_path}")
            except OSError:
                pass


def main():
    parser = argparse.ArgumentParser(description="Wazuh AI Inference Daemon")
    parser.add_argument("-t", "--test-config", action="store_true", help="Test configuration and exit")
    parser.add_argument("--socket", default=DEFAULT_SOCKET_PATH, help=f"Unix Domain Socket path (default: {DEFAULT_SOCKET_PATH})")
    parser.add_argument("--ait-model", default=DEFAULT_AIT_MODEL_DIR, help="Directory for Linux ait model")
    parser.add_argument("--comiset-model", default=DEFAULT_COMISET_MODEL_DIR, help="Directory for Windows comiset model")
    parser.add_argument("--device", default="cpu", choices=["cpu", "cuda"], help="Inference device (cpu or cuda)")
    args = parser.parse_args()

    if args.test_config:
        if not os.path.exists(args.ait_model) or not os.path.exists(args.comiset_model):
            logger.error(f"Models not found: ait={args.ait_model}, comiset={args.comiset_model}")
            sys.exit(1)
        sys.exit(0)

    daemon = AIDaemon(
        socket_path=args.socket,
        ait_model_dir=args.ait_model,
        comiset_model_dir=args.comiset_model,
        device=args.device
    )

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    def shutdown():
        logger.info("Shutdown signal received.")
        for task in asyncio.all_tasks(loop):
            task.cancel()
        daemon.cleanup()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, shutdown)
        except (NotImplementedError, RuntimeError):
            pass

    try:
        loop.run_until_complete(daemon.start())
    except (KeyboardInterrupt, asyncio.CancelledError):
        logger.info("AI Daemon stopped.")
    finally:
        daemon.cleanup()
        loop.close()


if __name__ == "__main__":
    main()
