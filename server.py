#!/usr/bin/env python3
"""
Payload Entropy Studio - Sovereign Standalone Web & REST Server
Listens on http://127.0.0.1:8080 by default.
"""

import os
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent
SRC_DIR = ROOT_DIR / "src"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from payload_entropy_studio.ui_server import run_ui_server

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    host = os.environ.get("HOST", "127.0.0.1")
    print(f"⚡ Starting Payload Entropy Studio on http://{host}:{port} ...")
    server = run_ui_server(host=host, port=port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutdown requested.")
    finally:
        server.server_close()
