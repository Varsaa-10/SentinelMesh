import json
from datetime import datetime
import os

LOG_FILE = "baseline/logs.json"

def log_event(scenario_id, alert, detected):
    log = {
        "scenario_id": scenario_id,
        "timestamp": str(datetime.now()),
        "alert": alert,
        "detected": detected
    }

    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(log) + "\n")