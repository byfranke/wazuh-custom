#!/var/ossec/framework/python/bin/python3
import json
import sys
import os
import re
import logging
import uuid
from thehive4py import TheHiveApi
from thehive4py.types.alert import InputAlert, InputCustomFieldValue
from thehive4py.types.observable import InputObservable

#  <integration>
#    <name>custom-thehive</name>
#    <hook_url>http://<thehive-ip>:9000</hook_url>
#    <api_key><SUA-API></api_key>
#    <alert_format>json</alert_format>
#  </integration>

#start user config
# Global vars

#threshold for wazuh rules level
lvl_threshold=5
#threshold for suricata rules level
suricata_lvl_threshold=3

debug_enabled = False
#info about created alert
info_enabled = True

#end user config

# Set paths
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
log_file = '{0}/logs/integrations.log'.format(pwd)
logger = logging.getLogger(__name__)
#set logging level
logger.setLevel(logging.WARNING)
if info_enabled:
    logger.setLevel(logging.INFO)
if debug_enabled:
    logger.setLevel(logging.DEBUG)
# create the logging file handler
fh = logging.FileHandler(log_file)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
fh.setFormatter(formatter)
logger.addHandler(fh)



def main(args):
    logger.debug('#start main')
    logger.debug('#get alert file location')
    alert_file_location = args[1]
    logger.debug('#get TheHive url')
    thive = args[3]
    logger.debug('#get TheHive api key')
    thive_api_key = args[2]
    thive_api = TheHiveApi(url=thive, apikey=thive_api_key)
    logger.debug('#open alert file')
    w_alert = json.load(open(alert_file_location))
    logger.debug('#alert data')
    logger.debug(str(w_alert))
    logger.debug('#gen json to dot-key-text')
    alt = pr(w_alert,'',[])
    logger.debug('#formatting description')
    format_alt = md_format(alt)
    logger.debug('#search artifacts')
    artifacts_dict = artifact_detect(format_alt)
    alert = generate_alert(format_alt, artifacts_dict, w_alert)
    logger.debug('#threshold filtering')
    if w_alert['rule']['groups']==['ids','suricata']:
        #checking the existence of the data.alert.severity field
        if 'data' in w_alert.keys():
            if 'alert' in w_alert['data']:
                #checking the level of the source event
                if int(w_alert['data']['alert']['severity'])<=suricata_lvl_threshold:
                    send_alert(alert, thive_api)
    elif int(w_alert['rule']['level'])>=lvl_threshold:
        #if the event is different from suricata AND suricata-event-type: alert check lvl_threshold
        send_alert(alert, thive_api)


def pr(data,prefix, alt):
    for key,value in data.items():
        if hasattr(value,'keys'):
            pr(value,prefix+'.'+str(key),alt=alt)
        else:
            alt.append((prefix+'.'+str(key)+'|||'+str(value)))
    return alt



def md_format(alt,format_alt=''):
    md_title_dict = {}
    #sorted with first key
    for now in alt:
        now = now[1:]
        #fix first key last symbol
        dot = now.split('|||')[0].find('.')
        if dot==-1:
            md_title_dict[now.split('|||')[0]] =[now]
        else:
            if now[0:dot] in md_title_dict.keys():
                (md_title_dict[now[0:dot]]).append(now)
            else:
                md_title_dict[now[0:dot]]=[now]
    for now in md_title_dict.keys():
        format_alt+='### '+now.capitalize()+'\n'+'| key | val |\n| ------ | ------ |\n'
        for let in md_title_dict[now]:
            key,val = let.split('|||')[0],let.split('|||')[1]
            format_alt+='| **' + key + '** | ' + val + ' |\n'
    return format_alt


def artifact_detect(format_alt):
    artifacts_dict = {}
    # IPs
    artifacts_dict['ip'] = re.findall(r'\d+\.\d+\.\d+\.\d+',format_alt)
    # URLs
    artifacts_dict['url'] =  re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',format_alt)
    # Domains from URLs
    artifacts_dict['domain'] = []
    for now in artifacts_dict['url']:
        artifacts_dict['domain'].append(now.split('//')[1].split('/')[0])
    # Email addresses
    artifacts_dict['mail'] = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', format_alt)
    # MD5 hashes
    artifacts_dict['hash'] = re.findall(r'\b[a-fA-F0-9]{32}\b', format_alt)
    # SHA1 hashes
    artifacts_dict['hash'].extend(re.findall(r'\b[a-fA-F0-9]{40}\b', format_alt))
    # SHA256 hashes
    artifacts_dict['hash'].extend(re.findall(r'\b[a-fA-F0-9]{64}\b', format_alt))
    # Filenames (common extensions)
    artifacts_dict['filename'] = re.findall(r'\b[\w\-]+\.(exe|dll|bat|ps1|sh|py|jar|vbs|js|cmd|msi|scr|com|pif)\b', format_alt, re.IGNORECASE)
    # User accounts (patterns like user: username or User=username)
    artifacts_dict['user-account'] = re.findall(r'(?:user|username|account)[:\s=]+([a-zA-Z0-9._-]+)', format_alt, re.IGNORECASE)

    return artifacts_dict


def generate_alert(format_alt, artifacts_dict,w_alert):
    #generate alert sourceRef
    sourceRef = str(uuid.uuid4())[0:6]
    observables = []

    # Extract agent info
    if 'agent' in w_alert.keys():
        if 'ip' not in w_alert['agent'].keys():
            w_alert['agent']['ip']='no agent ip'
    else:
        w_alert['agent'] = {'id':'no agent id', 'name':'no agent name'}

    # Create observables from detected artifacts
    for key,value in artifacts_dict.items():
        for val in value:
            if val:  # Only add non-empty values
                observables.append(InputObservable(dataType=key, data=val))

    # Map Wazuh alert level to TheHive severity (1=LOW, 2=MEDIUM, 3=HIGH, 4=CRITICAL)
    alert_level = w_alert['rule']['level']
    if alert_level >= 15:
        severity = 4  # CRITICAL
    elif alert_level >= 12:
        severity = 3  # HIGH
    elif alert_level >= 7:
        severity = 2  # MEDIUM
    else:
        severity = 1  # LOW

    # Build comprehensive tags list
    tags = []
    tags.append('rule:' + str(w_alert['rule']['id']))
    tags.append('level:' + str(alert_level))

    # Add rule groups as tags
    if 'groups' in w_alert['rule']:
        for group in w_alert['rule']['groups']:
            tags.append('group:' + group)

    # Add agent info as tags
    if w_alert['agent']['id'] != 'no agent id':
        tags.append('agent:' + str(w_alert['agent']['name']))
        tags.append('agent_id:' + str(w_alert['agent']['id']))

    # Add MITRE ATT&CK tags if present
    if 'rule' in w_alert and 'mitre' in w_alert['rule']:
        mitre_data = w_alert['rule']['mitre']
        if isinstance(mitre_data, dict):
            if 'id' in mitre_data:
                for mitre_id in mitre_data['id']:
                    tags.append('mitre:' + mitre_id)
        elif isinstance(mitre_data, list):
            for item in mitre_data:
                if isinstance(item, dict) and 'id' in item:
                    tags.append('mitre:' + item['id'])

    # Add location/manager info
    if 'manager' in w_alert:
        tags.append('manager:' + str(w_alert['manager']['name']))

    # Set PAP (Protocol for Amber/Privacy) based on severity
    if severity >= 3:
        pap = 2  # AMBER - Limited distribution
    else:
        pap = 1  # GREEN - Community sharing

    # Build custom fields for structured metadata
    custom_fields = {}

    # Agent information
    if w_alert['agent']['id'] != 'no agent id':
        custom_fields['wazuh-agent-id'] = InputCustomFieldValue(string=str(w_alert['agent']['id']))
        custom_fields['wazuh-agent-name'] = InputCustomFieldValue(string=str(w_alert['agent']['name']))
        if 'ip' in w_alert['agent'] and w_alert['agent']['ip'] != 'no agent ip':
            custom_fields['wazuh-agent-ip'] = InputCustomFieldValue(string=str(w_alert['agent']['ip']))

    # Rule information
    custom_fields['wazuh-rule-level'] = InputCustomFieldValue(integer=alert_level)
    custom_fields['wazuh-rule-id'] = InputCustomFieldValue(string=str(w_alert['rule']['id']))

    if 'groups' in w_alert['rule']:
        custom_fields['wazuh-rule-groups'] = InputCustomFieldValue(string=', '.join(w_alert['rule']['groups']))

    # Timestamp
    if 'timestamp' in w_alert:
        custom_fields['wazuh-timestamp'] = InputCustomFieldValue(string=str(w_alert['timestamp']))

    # Location/decoder info
    if 'location' in w_alert:
        custom_fields['wazuh-location'] = InputCustomFieldValue(string=str(w_alert['location']))

    if 'decoder' in w_alert and 'name' in w_alert['decoder']:
        custom_fields['wazuh-decoder'] = InputCustomFieldValue(string=str(w_alert['decoder']['name']))

    # Manager info
    if 'manager' in w_alert and 'name' in w_alert['manager']:
        custom_fields['wazuh-manager'] = InputCustomFieldValue(string=str(w_alert['manager']['name']))

    # Create the alert
    alert = InputAlert(
              title=w_alert['rule']['description'],
              tlp=2,  # AMBER - Limited disclosure
              pap=pap,
              tags=tags,
              severity=severity,
              description=format_alt,
              type='wazuh_alert',
              source='wazuh',
              sourceRef=sourceRef,
              observables=observables,
              customFields=custom_fields
    )
    return alert




def send_alert(alert, thive_api):
    try:
        response = thive_api.alert.create(alert)
        if isinstance(response, dict):
            alert_id = response.get('_id', response.get('id', 'unknown'))
            logger.info('Create TheHive alert: '+ str(alert_id))
        else:
            logger.info('Create TheHive alert: '+ str(response.id))
    except Exception as e:
        logger.error('Error create TheHive alert: {}'.format(str(e)))



if __name__ == "__main__":

    try:
       logger.debug('debug mode') # if debug enabled       
       # Main function
       main(sys.argv)

    except Exception:
       logger.exception('EGOR')
