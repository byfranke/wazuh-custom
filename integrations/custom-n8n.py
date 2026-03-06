#!/usr/bin/env python3

import sys
import requests
import json

# Input args
alert_file = sys.argv[1]
user = sys.argv[2].split(":")[0]  # Parsed but not used
hook_url = sys.argv[3]

# Read alerts line by line and send each as a POST to webhook
with open(alert_file, 'r') as f:
    for line in f:
        try:
            alert_json = json.loads(line.strip())
            response = requests.post(
                hook_url,
                json=alert_json,
                headers={"Content-Type": "application/json"}
            )
            response.raise_for_status()
        except json.JSONDecodeError:
            print("Invalid JSON line, skipping...")
        except requests.exceptions.RequestException as e:
            print(f"Failed to send alert: {e}", file=sys.stderr)

sys.exit(0)#!/usr/bin/env python3

import sys
import requests
import json

# Input args
alert_file = sys.argv[1]
user = sys.argv[2].split(":")[0]  # Parsed but not used
hook_url = sys.argv[3]

# Read alerts line by line and send each as a POST to webhook
with open(alert_file, 'r') as f:
    for line in f:
        try:
            alert_json = json.loads(line.strip())
            response = requests.post(
                hook_url,
                json=alert_json,
                headers={"Content-Type": "application/json"}
            )
            response.raise_for_status()
        except json.JSONDecodeError:
            print("Invalid JSON line, skipping...")
        except requests.exceptions.RequestException as e:
            print(f"Failed to send alert: {e}", file=sys.stderr)

sys.exit(0)
