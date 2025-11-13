#!/usr/bin/env python3

import sys
import requests
import json
from datetime import datetime
from requests.auth import HTTPBasicAuth

"""
Enhanced Discord integration for Wazuh
ossec.conf configuration structure:
 <integration>
     <name>custom-discord</name>
     <hook_url>https://discord.com/api/webhooks/XXXXXXXXXXX</hook_url>
     <alert_format>json</alert_format>
 </integration>
"""

def format_timestamp(timestamp_str):
    """Format timestamp to readable format"""
    try:
        dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        return dt.strftime('%Y-%m-%d %H:%M:%S UTC')
    except:
        return timestamp_str

def get_severity_emoji(level):
    """Get emoji based on alert level"""
    if level < 5:
        return "[MED]"
    elif level <= 7:
        return "[HIGH]"
    else:
        return "[CRIT]"

def safe_get(data, keys, default="N/A"):
    """Safely get nested dictionary values"""
    try:
        for key in keys:
            data = data[key]
        return data
    except (KeyError, TypeError):
        return default

# read configuration
alert_file = sys.argv[1]
user = sys.argv[2].split(":")[0]
hook_url = sys.argv[3]

# read alert file
with open(alert_file) as f:
    alert_json = json.loads(f.read())

# extract alert fields
alert_level = alert_json["rule"]["level"]
rule_id = alert_json["rule"]["id"]
description = alert_json["rule"]["description"]
timestamp = alert_json.get("timestamp", "N/A")

# colors from https://gist.github.com/thomasbnt/b6f455e2c7d743b796917fa3c205f812
if alert_level < 5:
    color = "5763719"  # green
elif alert_level <= 7:
    color = "16705372"  # yellow
else:
    color = "15548997"  # red

# agent details
if "agentless" in alert_json:
    agent_name = "agentless"
    agent_id = "agentless"
    agent_ip = "N/A"
else:
    agent_name = safe_get(alert_json, ["agent", "name"])
    agent_id = safe_get(alert_json, ["agent", "id"])
    agent_ip = safe_get(alert_json, ["agent", "ip"])

# source IP information
src_ip = safe_get(alert_json, ["data", "srcip"])
if src_ip == "N/A":
    src_ip = safe_get(alert_json, ["srcip"])
if src_ip == "N/A":
    src_ip = safe_get(alert_json, ["data", "src_ip"])

# additional security information
src_port = safe_get(alert_json, ["data", "srcport"])
dst_ip = safe_get(alert_json, ["data", "dstip"])
dst_port = safe_get(alert_json, ["data", "dstport"])
src_user = safe_get(alert_json, ["data", "srcuser"])
protocol = safe_get(alert_json, ["data", "protocol"])

# file information for syscheck events
file_path = safe_get(alert_json, ["syscheck", "path"])
file_size = safe_get(alert_json, ["syscheck", "size_after"])
file_permissions = safe_get(alert_json, ["syscheck", "perm_after"])

# MITRE ATT&CK information
mitre_tactics = safe_get(alert_json, ["rule", "mitre", "tactic"], [])
mitre_techniques = safe_get(alert_json, ["rule", "mitre", "technique"], [])
mitre_id = safe_get(alert_json, ["rule", "mitre", "id"], [])

# build fields array
fields = [
    {
        "name": f"{get_severity_emoji(alert_level)} Severity Level",
        "value": str(alert_level),
        "inline": True
    },
    {
        "name": "Timestamp",
        "value": format_timestamp(timestamp),
        "inline": True
    },
    {
        "name": "Agent",
        "value": f"{agent_name} (ID: {agent_id})",
        "inline": True
    }
]

# Add agent IP if available
if agent_ip != "N/A":
    fields.append({
        "name": "Agent IP",
        "value": agent_ip,
        "inline": True
    })

# Add source IP information if available
if src_ip != "N/A":
    src_info = src_ip
    if src_port != "N/A":
        src_info += f":{src_port}"
    fields.append({
        "name": "Source IP",
        "value": src_info,
        "inline": True
    })

# Add destination information if available
if dst_ip != "N/A":
    dst_info = dst_ip
    if dst_port != "N/A":
        dst_info += f":{dst_port}"
    fields.append({
        "name": "Destination",
        "value": dst_info,
        "inline": True
    })

# Add user information if available
if src_user != "N/A":
    fields.append({
        "name": "User",
        "value": src_user,
        "inline": True
    })

# Add protocol if available
if protocol != "N/A":
    fields.append({
        "name": "Protocol",
        "value": protocol,
        "inline": True
    })

# Add file information for file integrity monitoring
if file_path != "N/A":
    fields.append({
        "name": "File Path",
        "value": file_path,
        "inline": False
    })
    if file_size != "N/A":
        fields.append({
            "name": "File Size",
            "value": f"{file_size} bytes",
            "inline": True
        })
    if file_permissions != "N/A":
        fields.append({
            "name": "Permissions",
            "value": file_permissions,
            "inline": True
        })

# Add MITRE ATT&CK information if available
if mitre_tactics or mitre_techniques:
    mitre_info = []
    if mitre_id:
        mitre_info.append(f"**IDs:** {', '.join(mitre_id)}")
    if mitre_tactics:
        mitre_info.append(f"**Tactics:** {', '.join(mitre_tactics)}")
    if mitre_techniques:
        mitre_info.append(f"**Techniques:** {', '.join(mitre_techniques)}")

    fields.append({
        "name": "MITRE ATT&CK",
        "value": "\n".join(mitre_info),
        "inline": False
    })

# Add full log data if available (truncated for readability)
full_log = safe_get(alert_json, ["full_log"])
if full_log != "N/A" and len(full_log) > 0:
    truncated_log = full_log[:500] + "..." if len(full_log) > 500 else full_log
    fields.append({
        "name": "Log Details",
        "value": f"```{truncated_log}```",
        "inline": False
    })

# combine message details
payload = json.dumps({
    "content": "",
    "embeds": [
        {
            "title": f"Wazuh Security Alert - Rule {rule_id}",
            "color": int(color),
            "description": description,
            "fields": fields,
            "footer": {
                "text": f"Wazuh SIEM • Rule ID: {rule_id}"
            },
            "timestamp": datetime.now().isoformat()
        }
    ]
})

# send message to discord
try:
    r = requests.post(hook_url, data=payload, headers={"content-type": "application/json"})
    if r.status_code != 204:
        print(f"Error sending Discord notification: {r.status_code} - {r.text}")
        sys.exit(1)
except Exception as e:
    print(f"Error sending Discord notification: {str(e)}")
    sys.exit(1)
