#!/usr/bin/env python3
import json, os, sys, time, requests

API_TOKEN = "****"
ZONE_ID = "****"

def cf_block(ip):
    url = f"https://api.cloudflare.com/client/v4/zones/{ZONE_ID}/firewall/access_rules/rules"
    payload = {
        "mode": "block",
        "configuration": {"target": "ip", "value": ip},
        "notes": f"Blocked by Wazuh {int(time.time())}"
    }
    headers = {"Authorization": f"Bearer {API_TOKEN}",
               "Content-Type": "application/json"}
    r = requests.post(url, headers=headers, json=payload, timeout=10)
    return r.status_code, r.text

def main():
    if len(sys.argv) < 2:
        print("usage: cloudflare-ban.py <ip>")
        sys.exit(1)
    status, body = cf_block(sys.argv[1])
    print(json.dumps({"status": status, "response": body}))

if __name__ == "__main__":
    main()
