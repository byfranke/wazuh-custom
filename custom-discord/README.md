# Custom Discord Integration with Wazuh

## Overview

This project integrates **Wazuh** with **Discord** to deliver real-time security alerts to a Discord channel via **webhooks**. Alerts are formatted as rich embeds, including severity, rule details, agent data, source/destination IPs, and optional MITRE ATT&CK mappings—improving visibility and incident response.

<img width="473" height="356" alt="Screenshot 2025-10-06 at 15 30 54" src="https://github.com/user-attachments/assets/d45541b0-ef1d-4880-aa2e-ecef5610daee" />
<img width="478" height="346" alt="Screenshot 2025-10-06 at 15 31" src="https://github.com/user-attachments/assets/401047df-baca-46ea-9540-e3bf53961b78" />


## Features

* JSON-based alert ingestion from Wazuh integrations
* Color-coded embeds by alert level (low/medium/high)
* Agent details (name, ID, IP)
* Source/Destination IP:Port (when present)
* Optional MITRE ATT&CK tactics/techniques (when present)
* Truncated `full_log` preview for readability
* Works with **level thresholds** and/or **specific rule_id lists**

## Project Structure

```
custom-discord-wazuh/
├─ custom-discord           # Wazuh integration wrapper (shell script)
├─ custom-discord.py        # Python sender (Discord webhook)
├─ ossec.conf               # Example integration blocks
└─ LICENSE
```

### Key Components

* **`custom-discord`**
  Wrapper modeled after Wazuh’s Slack integration. Resolves the correct Python path and calls `custom-discord.py` with the original arguments from Wazuh.

* **`custom-discord.py`**
  Reads the alert JSON file provided by Wazuh, extracts fields (rule, level, agent, IPs, ports, MITRE, full_log), builds a Discord embed, and POSTs to the webhook URL.

* **`ossec.conf` (examples)**
  Two sample blocks:

  * Trigger by **level** (e.g., `level >= 8`)
  * Trigger by **specific rules** (e.g., `5710,5715,5716,60107,100631,100632`)

## Requirements

* Wazuh Manager **4.x**
* Python **3.x** on the Wazuh Manager
* Python package: `requests`
* A **Discord Webhook URL** for the target channel

## Installation

> Run these on the **Wazuh Manager**.

1. **Install dependencies**

```bash
sudo apt-get update
sudo apt-get install -y python3 python3-pip
pip3 install --upgrade requests
```

2. **Copy files to Wazuh integrations directory**

```bash
sudo cp custom-discord /var/ossec/integrations/
sudo cp custom-discord.py /var/ossec/integrations/custom-discord.py
sudo chmod 750 /var/ossec/integrations/custom-discord /var/ossec/integrations/custom-discord.py
sudo chown root:wazuh /var/ossec/integrations/custom-discord /var/ossec/integrations/custom-discord.py
```

> If your group is `ossec` instead of `wazuh`, adjust `chown` accordingly.

3. **Configure `ossec.conf`**
   Add one or both integration blocks inside the `<ossec_config>`:

**Trigger by level (example: level ≥ 8)**

```xml
<integration>
  <name>custom-discord</name>
  <hook_url>https://discord.com/api/webhooks/XXXXXXXXXXX</hook_url>
  <alert_format>json</alert_format>
  <level>8</level>
</integration>
```

**Trigger by specific rules**

```xml
<integration>
  <name>custom-discord</name>
  <hook_url>https://discord.com/api/webhooks/XXXXXXXXXXX</hook_url>
  <alert_format>json</alert_format>
  <rule_id>5710,5715,5716,60107,100631,100632</rule_id>
</integration>
```

4. **Restart Wazuh Manager**

```bash
sudo systemctl restart wazuh-manager
```

## How It Works

1. Wazuh matches an alert (by level and/or `rule_id`)
2. Wazuh runs `custom-discord` → which invokes `custom-discord.py`
3. The Python script parses the alert JSON and builds a Discord embed
4. The message is POSTed to your Discord webhook

## Testing

* **Generate a test alert** that matches your level/rule criteria, then check the Discord channel.
* Review logs if nothing arrives:

  * `/var/ossec/logs/integrations.log`
  * `/var/ossec/logs/ossec.log`

## Configuration Tips

* Tune the `<level>` and `<rule_id>` filters to reduce noise
* Use a dedicated channel/webhook for security alerts
* Rotate the webhook URL if it’s exposed
* Consider Discord rate limits (bursting many alerts can be throttled)

## Troubleshooting

* **No messages in Discord**

  * Verify the **webhook URL** is correct and active
  * Check `integrations.log` for Python/HTTP errors
  * Ensure the event meets the `<level>` or `<rule_id>` filters
* **HTTP 4xx/5xx errors**

  * Webhook permissions/rate limits or malformed payload
* **Missing fields in embeds**

  * Some fields are optional in alerts; the script falls back to `N/A` gracefully


## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Open a Pull Request

---

## Support My Work

If you appreciate what I do and would like to contribute, any amount is welcome. Your support helps fuel my journey and keeps me motivated to keep creating, learning, and sharing.

[![Donate](https://img.shields.io/badge/Support-Development-blue?style=for-the-badge\&logo=github)](https://buy.byfranke.com/b/8wM03kb3u7THeIgaEE)

---

### Let’s Talk!

Want to collaborate or ask questions? Reach out via [byfranke.com](https://byfranke.com/#Contact).

**Together, we can make the digital world safer!**

