#!/usr/bin/env python3
"""
Cloudflare Integration for Wazuh
Blocks malicious IPs on Cloudflare firewall
Manual unblock required
"""

import sys
import json
import requests
from datetime import datetime

# Configurações Cloudflare
API_TOKEN = "xxxx"
ZONE_ID = "xxxx"

# Whitelist de IPs que NUNCA serão bloqueados
WHITELIST_IPS = ["xx.xx.xx.xx"]

# Log file
LOG_FILE = "/var/ossec/logs/integrations.log"

# Headers Cloudflare
HEADERS = {
    "Authorization": f"Bearer {API_TOKEN}",
    "Content-Type": "application/json"
}

def log(msg):
    """Log para arquivo"""
    timestamp = datetime.now().strftime('%Y/%m/%d %H:%M:%S')
    try:
        with open(LOG_FILE, 'a') as f:
            f.write(f"{timestamp} custom-cloudflare: {msg}\n")
    except Exception as e:
        print(f"Error writing to log: {e}", file=sys.stderr)

def safe_get(data, keys, default="N/A"):
    """Safely get nested dictionary values"""
    try:
        for key in keys:
            data = data[key]
        return data
    except (KeyError, TypeError):
        return default

def is_whitelisted(ip):
    """Verifica se IP está na whitelist"""
    return ip in WHITELIST_IPS

def cf_block(ip, alert_info):
    """Bloqueia IP no Cloudflare"""
    url = f"https://api.cloudflare.com/client/v4/zones/{ZONE_ID}/firewall/access_rules/rules"

    # Monta nota descritiva
    rule_id = alert_info.get('rule_id', 'N/A')
    rule_desc = alert_info.get('rule_desc', 'Unknown attack')
    timestamp = alert_info.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

    payload = {
        "mode": "block",
        "configuration": {
            "target": "ip",
            "value": ip
        },
        "notes": f"Wazuh Alert {rule_id}: {rule_desc} at {timestamp}"
    }

    try:
        response = requests.post(url, headers=HEADERS, json=payload, timeout=10)

        if response.status_code == 200:
            log(f"Successfully blocked IP: {ip} (Rule: {rule_id})")
            return True
        elif response.status_code == 409:
            # IP já está bloqueado
            log(f"IP already blocked: {ip}")
            return True
        else:
            log(f"Failed to block IP {ip}: Status {response.status_code} - {response.text}")
            return False

    except Exception as e:
        log(f"Exception blocking IP {ip}: {e}")
        return False

def main():
    """Função principal da Integration"""

    # Ler argumentos do Wazuh Integration
    # argv[1] = alert file path
    # argv[2] = user (api_key from ossec.conf, ignored here)
    # argv[3] = hook_url (ignored for Cloudflare)

    if len(sys.argv) < 2:
        log("Error: No alert file provided")
        sys.exit(1)

    alert_file = sys.argv[1]

    # Ler arquivo de alerta
    try:
        with open(alert_file) as f:
            alert_json = json.loads(f.read())
    except Exception as e:
        log(f"Error reading alert file {alert_file}: {e}")
        sys.exit(1)

    # Extrair informações do alerta
    rule_id = safe_get(alert_json, ["rule", "id"])
    rule_desc = safe_get(alert_json, ["rule", "description"])
    alert_level = safe_get(alert_json, ["rule", "level"], 0)
    timestamp = safe_get(alert_json, ["timestamp"])

    # Extrair IP de origem
    src_ip = safe_get(alert_json, ["data", "srcip"])

    # Fallback: tentar outros campos
    if src_ip == "N/A":
        src_ip = safe_get(alert_json, ["srcip"])
    if src_ip == "N/A":
        src_ip = safe_get(alert_json, ["data", "win", "eventdata", "ipAddress"])

    if src_ip == "N/A":
        log(f"No source IP found in alert {rule_id}")
        sys.exit(0)

    log(f"Processing alert: Rule {rule_id} (Level {alert_level}) - IP: {src_ip}")

    # Verificar whitelist
    if is_whitelisted(src_ip):
        log(f"IP {src_ip} is whitelisted, skipping block")
        sys.exit(0)

    # Bloquear IP no Cloudflare
    alert_info = {
        'rule_id': rule_id,
        'rule_desc': rule_desc,
        'timestamp': timestamp
    }

    success = cf_block(src_ip, alert_info)

    if success:
        log(f"IP {src_ip} successfully processed")
        sys.exit(0)
    else:
        log(f"Failed to process IP {src_ip}")
        sys.exit(1)

if __name__ == "__main__":
    main()
