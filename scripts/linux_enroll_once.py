import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent import agent

server_url = os.environ.get("ATOR_SERVER_URL", "http://127.0.0.1:8000")
mode = os.environ.get("ATOR_MODE", "once")

cfg = agent.load_config()
cfg["server_url"] = server_url
if not cfg.get("api_key") or not cfg.get("client_id"):
    print(json.dumps(agent.enroll(cfg)))

if mode == "enroll":
    sys.exit(0)

agent.flush_spool(cfg)
payload = agent.run_collection()
try:
    agent.send_payload(cfg, payload)
    print(json.dumps({"status": "sent", "collection_id": payload["manifest"]["collection_id"]}))
except Exception as exc:
    path = agent.spool_payload(cfg, payload)
    print(json.dumps({"status": "spooled", "path": path, "reason": str(exc)}))
