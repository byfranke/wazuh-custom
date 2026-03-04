# Copyright (C) 2015, Wazuh Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

import json
import os
import sys
from datetime import datetime

# Exit error codes
ERR_NO_REQUEST_MODULE = 1
ERR_BAD_ARGUMENTS = 2
ERR_FILE_NOT_FOUND = 6
ERR_INVALID_JSON = 7

try:
    import requests
except Exception:
    print("No module 'requests' found. Install: pip install requests")
    sys.exit(ERR_NO_REQUEST_MODULE)

# ossec.conf configuration structure
#  <integration>
#      <name>slack</name>
#      <hook_url>https://hooks.slack.com/services/XXXXXXXXXXXXXX</hook_url>
#      <alert_format>json</alert_format>
#      <options>JSON</options> <!-- Replace with your custom JSON object -->
#  </integration>

# Global vars
debug_enabled = False
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
json_alert = {}
json_options = {}

# Log path
LOG_FILE = f'{pwd}/logs/integrations.log'

# Constants
ALERT_INDEX = 1
WEBHOOK_INDEX = 3


def main(args):
    global debug_enabled
    try:
        # Read arguments
        bad_arguments: bool = False
        if len(args) >= 4:
            msg = '{0} {1} {2} {3} {4}'.format(
                args[1], args[2], args[3], args[4] if len(args) > 4 else '', args[5] if len(args) > 5 else ''
            )
            debug_enabled = len(args) > 4 and args[4] == 'debug'
        else:
            msg = '# ERROR: Wrong arguments'
            bad_arguments = True

        # Logging the call
        with open(LOG_FILE, 'a') as f:
            f.write(msg + '\n')

        if bad_arguments:
            debug('# ERROR: Exiting, bad arguments. Inputted: %s' % args)
            sys.exit(ERR_BAD_ARGUMENTS)

        # Core function
        process_args(args)

    except Exception as e:
        debug(str(e))
        raise


def process_args(args) -> None:
    """This is the core function, creates a message with all valid fields
    and overwrite or add with the optional fields

    Parameters
    ----------
    args : list[str]
        The argument list from main call
    """
    debug('# Running Slack script')

    # Read args
    alert_file_location: str = args[ALERT_INDEX]
    webhook: str = args[WEBHOOK_INDEX]
    options_file_location: str = ''

    # Look for options file location
    for idx in range(4, len(args)):
        if args[idx][-7:] == 'options':
            options_file_location = args[idx]
            break

    # Load options. Parse JSON object.
    json_options = get_json_options(options_file_location)
    debug(f"# Opening options file at '{options_file_location}' with '{json_options}'")

    # Load alert. Parse JSON object.
    json_alert = get_json_alert(alert_file_location)
    debug(f"# Opening alert file at '{alert_file_location}' with '{json_alert}'")

    debug('# Generating message')
    msg: any = generate_msg(json_alert, json_options)

    if not len(msg):
        debug('# ERROR: Empty message')
        raise Exception

    debug(f'# Sending message {msg} to Slack server')
    send_msg(msg, webhook)


def debug(msg: str) -> None:
    """Log the message in the log file with the timestamp, if debug flag
    is enabled

    Parameters
    ----------
    msg : str
        The message to be logged.
    """
    if debug_enabled:
        print(msg)
        with open(LOG_FILE, 'a') as f:
            f.write(msg + '\n')


def format_timestamp(timestamp_str):
    """Format timestamp to readable format"""
    try:
        dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        return dt.strftime('%Y-%m-%d %H:%M:%S UTC')
    except:
        return timestamp_str


def get_severity_label(level):
    """Get label based on alert level"""
    if level <= 4:
        return "[LOW]"
    elif level <= 7:
        return "[MED]"
    elif level <= 10:
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


def generate_msg(alert: any, options: any) -> any:
    """Generate the JSON object with the message to be send

    Parameters
    ----------
    alert : any
        JSON alert object.
    options: any
        JSON options object.

    Returns
    -------
    msg: str
        The JSON message to send
    """
    level = alert['rule']['level']
    rule_id = alert['rule']['id']
    description = alert['rule']['description'] if 'description' in alert['rule'] else 'N/A'
    timestamp = alert.get('timestamp', 'N/A')

    # Set color based on severity
    if level <= 4:
        color = 'good'
    elif level <= 7:
        color = 'warning'
    elif level <= 10:
        color = 'danger'
    else:
        color = '#8B0000'  # Dark red for critical

    # Main attachment
    msg = {}
    msg['color'] = color
    msg['pretext'] = f'{get_severity_label(level)} *Wazuh Security Alert*'
    msg['title'] = f'Rule {rule_id}: {description}'
    msg['title_link'] = ''

    # Build fields array with enhanced information
    msg['fields'] = []

    # Alert level and timestamp
    msg['fields'].append({
        'title': 'Severity Level',
        'value': str(level),
        'short': True
    })

    if timestamp != 'N/A':
        msg['fields'].append({
            'title': 'Timestamp',
            'value': format_timestamp(timestamp),
            'short': True
        })

    # Agent information
    if 'agent' in alert:
        agent_name = safe_get(alert, ['agent', 'name'])
        agent_id = safe_get(alert, ['agent', 'id'])
        agent_ip = safe_get(alert, ['agent', 'ip'])

        agent_info = f'{agent_name} (ID: {agent_id})'
        if agent_ip != "N/A":
            agent_info += f'\nIP: {agent_ip}'

        msg['fields'].append({
            'title': 'Agent',
            'value': agent_info,
            'short': True
        })
    elif 'agentless' in alert:
        msg['fields'].append({
            'title': 'Agentless Host',
            'value': alert['agentless']['host'],
            'short': True
        })

    # Location
    if 'location' in alert:
        msg['fields'].append({
            'title': 'Location',
            'value': alert['location'],
            'short': True
        })

    # Network information
    src_ip = safe_get(alert, ['data', 'srcip'])
    if src_ip == "N/A":
        src_ip = safe_get(alert, ['srcip'])
    if src_ip == "N/A":
        src_ip = safe_get(alert, ['data', 'src_ip'])

    if src_ip != "N/A":
        src_port = safe_get(alert, ['data', 'srcport'])
        src_info = src_ip
        if src_port != "N/A":
            src_info += f':{src_port}'
        msg['fields'].append({
            'title': 'Source IP',
            'value': src_info,
            'short': True
        })

    dst_ip = safe_get(alert, ['data', 'dstip'])
    if dst_ip != "N/A":
        dst_port = safe_get(alert, ['data', 'dstport'])
        dst_info = dst_ip
        if dst_port != "N/A":
            dst_info += f':{dst_port}'
        msg['fields'].append({
            'title': 'Destination',
            'value': dst_info,
            'short': True
        })

    # User information
    src_user = safe_get(alert, ['data', 'srcuser'])
    if src_user != "N/A":
        msg['fields'].append({
            'title': 'User',
            'value': src_user,
            'short': True
        })

    # Protocol
    protocol = safe_get(alert, ['data', 'protocol'])
    if protocol != "N/A":
        msg['fields'].append({
            'title': 'Protocol',
            'value': protocol,
            'short': True
        })

    # File information for FIM
    file_path = safe_get(alert, ['syscheck', 'path'])
    if file_path != "N/A":
        msg['fields'].append({
            'title': 'File Path',
            'value': f'`{file_path}`',
            'short': False
        })

        file_size = safe_get(alert, ['syscheck', 'size_after'])
        if file_size != "N/A":
            msg['fields'].append({
                'title': 'File Size',
                'value': f'{file_size} bytes',
                'short': True
            })

        file_permissions = safe_get(alert, ['syscheck', 'perm_after'])
        if file_permissions != "N/A":
            msg['fields'].append({
                'title': 'Permissions',
                'value': file_permissions,
                'short': True
            })

    # MITRE ATT&CK information
    mitre_tactics = safe_get(alert, ['rule', 'mitre', 'tactic'], [])
    mitre_techniques = safe_get(alert, ['rule', 'mitre', 'technique'], [])
    mitre_id = safe_get(alert, ['rule', 'mitre', 'id'], [])

    if mitre_tactics or mitre_techniques:
        mitre_info = []
        if mitre_id:
            mitre_info.append(f'*IDs:* {", ".join(mitre_id)}')
        if mitre_tactics:
            mitre_info.append(f'*Tactics:* {", ".join(mitre_tactics)}')
        if mitre_techniques:
            mitre_info.append(f'*Techniques:* {", ".join(mitre_techniques)}')

        msg['fields'].append({
            'title': 'MITRE ATT&CK',
            'value': '\n'.join(mitre_info),
            'short': False
        })

    # Add log details
    full_log = safe_get(alert, ['full_log'])
    if full_log != "N/A" and len(full_log) > 0:
        # Truncate very long logs
        if len(full_log) > 500:
            full_log = full_log[:500] + '...'
        msg['text'] = f'```{full_log}```'

    # Footer
    msg['footer'] = f'Wazuh SIEM | Rule ID: {rule_id}'
    msg['footer_icon'] = ''
    msg['ts'] = alert.get('id', int(datetime.now().timestamp()))

    # Apply custom options if provided
    if options:
        msg.update(options)

    # Create the full message
    attach = {'attachments': [msg]}

    return json.dumps(attach)


def send_msg(msg: str, url: str) -> None:
    """Send the message to the API

    Parameters
    ----------
    msg : str
        JSON message.
    url: str
        URL of the API.
    """
    headers = {'content-type': 'application/json', 'Accept-Charset': 'UTF-8'}
    res = requests.post(url, data=msg, headers=headers, timeout=10)
    debug('# Response received: %s' % res.json)


def get_json_alert(file_location: str) -> any:
    """Read JSON alert object from file

    Parameters
    ----------
    file_location : str
        Path to the JSON file location.

    Returns
    -------
    dict: any
        The JSON object read it.

    Raises
    ------
    FileNotFoundError
        If no JSON file is found.
    JSONDecodeError
        If no valid JSON file are used
    """
    try:
        with open(file_location) as alert_file:
            return json.load(alert_file)
    except FileNotFoundError:
        debug("# JSON file for alert %s doesn't exist" % file_location)
        sys.exit(ERR_FILE_NOT_FOUND)
    except json.decoder.JSONDecodeError as e:
        debug('Failed getting JSON alert. Error: %s' % e)
        sys.exit(ERR_INVALID_JSON)


def get_json_options(file_location: str) -> any:
    """Read JSON options object from file

    Parameters
    ----------
    file_location : str
        Path to the JSON file location.

    Returns
    -------
    dict: any
        The JSON object read it.

    Raises
    ------
    JSONDecodeError
        If no valid JSON file are used
    """
    try:
        with open(file_location) as options_file:
            return json.load(options_file)
    except FileNotFoundError:
        debug("# JSON file for options %s doesn't exist" % file_location)
    except BaseException as e:
        debug('Failed getting JSON options. Error: %s' % e)
        sys.exit(ERR_INVALID_JSON)


if __name__ == '__main__':
    main(sys.argv)