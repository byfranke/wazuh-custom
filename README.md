# Cloudflare Ban Integration with Wazuh

## Overview

This project provides integration between Wazuh (an open-source security monitoring platform) and Cloudflare's firewall, enabling automatic blocking and unblocking of malicious IP addresses through Cloudflare's API based on security events detected by Wazuh. This integration enhances your security posture by adding an additional layer of protection at the edge network level.

## Project Components

### Python Script (`cloudflare-ban.py`)
The main script that handles all interactions with Cloudflare's API. It includes the following key functions:

- **cf_block(ip)**: Creates a firewall rule to block a specific IP address
- **cf_find_rule(ip)**: Searches for existing firewall rules for a given IP
- **cf_unblock(ip)**: Removes blocking rules for a specific IP address
- **main()**: Processes command-line arguments and executes the appropriate action

### Wazuh Configuration (`ossec.conf`)
Contains the active response configuration for Wazuh, defining when and how the Python script should be triggered. The configuration includes:

- Command definition for the Cloudflare ban script
- Active response rules mapping
- Execution parameters and timing

### Apache Configuration (`apache2.config`)
Provides the necessary Apache configuration to correctly identify real client IPs when using Cloudflare, including:

- RemoteIP module configuration
- Cloudflare IP ranges setup
- Proper logging format for real IP addresses

## Technical Requirements

### Software Dependencies
- Python 3.x
- Python `requests` library
- Wazuh Server (tested with version 4.x)
- Apache2 with mod_remoteip enabled
- Active Cloudflare account with API access

### API Requirements
- Cloudflare API Token with the following permissions:
  - Zone.Firewall Services: Edit
  - Zone.Zone: Read
  - Zone.Zone Settings: Read
- Cloudflare Zone ID for the target domain

## Installation and Configuration

### 1. Python Script Setup
1. Clone this repository to your Wazuh server:
   ```bash
   git clone https://github.com/byfranke/cloudflare-ban.git
   ```

2. Install the required Python package:
   ```bash
   pip3 install requests
   ```

3. Configure the script with your Cloudflare credentials:
   - Edit `cloudflare-ban.py`
   - Replace `YOUR_API_TOKEN` with your Cloudflare API token
   - Replace `YOUR_ZONE_ID` with your Cloudflare Zone ID

4. Make the script executable:
   ```bash
   chmod +x cloudflare-ban.py
   ```

### 2. Apache Configuration
1. Enable the RemoteIP module:
   ```bash
   a2enmod remoteip
   ```

2. Configure Apache to use Cloudflare's IP ranges:
   - Copy the provided `apache2.config` to `/etc/apache2/conf-available/cloudflare.conf`
   - Enable the configuration:
     ```bash
     a2enconf cloudflare
     ```
   - Restart Apache:
     ```bash
     systemctl restart apache2
     ```

### 3. Wazuh Configuration
1. Add the command definition to your `ossec.conf`:
   ```xml
   <command>
     <name>cloudflare-ban</name>
     <executable>cloudflare-ban.py</executable>
     <expect>srcip</expect>
     <timeout_allowed>yes</timeout_allowed>
   </command>
   ```

2. Configure the active response:
   ```xml
   <active-response>
     <command>cloudflare-ban</command>
     <location>server</location>
     <rules_id>31151,31152</rules_id>
     <timeout>600</timeout>
   </active-response>
   ```

## Usage

### Manual Operation
The script can be run manually for testing or one-off operations:

```bash
# Block an IP
python3 cloudflare-ban.py block 1.2.3.4

# Unblock an IP
python3 cloudflare-ban.py unblock 1.2.3.4
```

### Automated Operation
Once configured, the system works automatically:

1. Wazuh monitors security events through its agents and log analysis
2. When a rule matching the active response configuration is triggered
3. The `cloudflare-ban.py` script is executed with the detected malicious IP
4. Cloudflare firewall rules are updated accordingly

## Maintenance

### Regular Tasks
1. Update Cloudflare IP ranges periodically in Apache configuration
2. Monitor Wazuh logs for any script execution errors
3. Review blocked IPs in Cloudflare dashboard periodically
4. Check and update API tokens before expiration

### Troubleshooting
- Check Wazuh's `/var/ossec/logs/active-responses.log` for script execution logs
- Verify API permissions if blocks are not being created
- Ensure proper IP formatting in logs and script execution
- Monitor Cloudflare's API rate limits

## Security Considerations

- Store API credentials securely and with restricted permissions
- Regularly rotate API tokens
- Monitor for false positives in blocking rules
- Implement appropriate timeouts for blocks
- Keep all components updated (Python, Wazuh, Apache)

## Limitations

- Cloudflare API rate limits may affect large-scale blocking operations
- Temporary blocks require manual tracking or custom implementation
- No built-in whitelist functionality (must be implemented separately)
- Depends on accurate client IP detection through Cloudflare headers

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

---

## Support My Work 

- **If you appreciate what I do and would like to contribute, any amount is welcome. Your support helps fuel my journey and keeps me motivated to keep creating, learning, and sharing. Thank you for being part of it!**

    [![Donate](https://img.shields.io/badge/Support-Development-blue?style=for-the-badge&logo=github)](https://donate.stripe.com/28o8zQ2wY3Dr57G001)

---

### Let’s Talk!
Want to collaborate or ask questions? Feel free to reach out via [byfranke.com](https://byfranke.com/#Contact). 

**Together, we can make the digital world safer!**


This project is licensed under the MIT License. See the author for more details.

## Support

For issues, questions, or contributions, please open an issue in the GitHub repository.
