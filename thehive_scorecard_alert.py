#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function
from __future__ import unicode_literals

from thehive4py.api import TheHiveApi
from thehive4py.models import Alert, AlertArtifact
import requests
import json
import uuid
import re
import os.path

## Calls SecurityScore Card's API to check for new issues.
def get_new_issues(url_new_issues):
   return call_sc_api(url_new_issues)

## Calls SecurityScore Card's API to get more data about the new isseues.
def get_data_about_new_issues(url_info):
    return call_sc_api(url_info)

## Calls SecurityScore Card's API to get info about the issue type of the new issues. (eg. getting the description and title of the issue type)
def get_data_about_issue_type(url_data):
    return call_sc_api(url_data)

## Call the API of Security Scorecard
def call_sc_api(url):
    try:
        r = requests.request("GET", url, headers=headers)
        r.raise_for_status()
        return r.json()
    except requests.exceptions.ConnectionError as err:
        raise SystemExit(err)
    except requests.exceptions.HTTPError as err:
        raise SystemExit(err)

## Creates observables. The targets are named diffrently depending on what type of issue it is.
## Hopefully covers the most cases, may miss to add some observable if it is not covered in these cases
def create_observables(response_issue_info):
    artifacts = []
    regex_ip = '^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)(\.(?!$)|$)){4}$'
    if 'initial_url' in response_issue_info:
        artifacts.append(AlertArtifact(dataType='url', data=response_issue_info['initial_url']))
    if 'final_url' in response_issue_info:
        artifacts.append(AlertArtifact(dataType='url', data=response_issue_info['final_url']))
    if 'target' in response_issue_info:
        if re.match(regex_ip, response_issue_info['target']):        
            artifacts.append(AlertArtifact(dataType='ip', data=response_issue_info['target']))
        else:
            artifacts.append(AlertArtifact(dataType='url', data=response_issue_info['target']))
    if 'src_ip' in response_issue_info:
        artifacts.append(AlertArtifact(dataType='ip', data=response_issue_info['src_ip']))
    elif 'connection_attributes' in response_issue_info:
        if 'dst_ip' in response_issue_info['connection_attributes']:
            artifacts.append(AlertArtifact(dataType='ip', data=response_issue_info['connection_attributes']['dst_ip']))
    return artifacts 

## Parsing the info about the new data. The different issues have different structures depending on which issue_type there are. 
## Different cases depending on the JSON-structure:
##              1. Plain Key/Value-pair. eg. "type: network_issue"
##              2. Value is a dict. eg. "type: { name: network_issue, severity: medium }"
##              3. Value is a list:
##                  a) just a plain list  eg. "type: [ network_issue, medium ]"
##                  b) a list of dicts eg. "type: [ { name: network_issue, severity: medium } ]"
##
## Returns a list with the parsed issue data.
def parse_new_issue_data(new_issue, response_issue_info):
    for issue_data_field in response_issue_info['entries']:
        issue_data = []
        for key, value in issue_data_field.items():
                if isinstance(value, dict):
                    issue_data.append('**{}:** \n\n'.format(str(key)))
                    for inner_key, inner_value in value.items():
                        issue_data.append('&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;***{}:*** {}\n\n'.format(str(inner_key), str(inner_value)))
                elif isinstance(value, list):
                    issue_data.append('**' + str(key) + ':**\n\n')
                    for inner_entry in value:
                        if isinstance(inner_entry, dict):
                            for deep_key, deep_value in inner_entry.items():
                                issue_data.append('&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;***{}:*** {}\n\n'.format(str(deep_key), str(deep_value)))
                            if len(value) > 1: issue_data.append('&nbsp;\n\n')
                        else:
                            issue_data.append('&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;***{}***\n\n'.format(str(inner_entry)))
                else:
                    if (key == 'parent_domain'):
                        domain = str(value)
                    if(key != 'count'):
                        issue_data.append('**{}:** {}\n\n'.format(str(key), str(value)))
        response_meta = get_data_about_issue_type(url_meta + new_issue['issue_type'])
        artifacts = create_observables(issue_data_field)
        new_issue_field =  {
                            "issue_type": new_issue['issue_type'], 
                            "factor": new_issue['factor'], 
                            "severity": new_issue['severity'], 
                            "title": response_meta['title'], 
                            "short_description": response_meta['short_description'], 
                            "domain": domain
                            }
        new_issue_field["data"] = issue_data
        new_issue_field["artifacts"] = artifacts
        new_issues_list.append(new_issue_field)

# Function for creating the alert object. Retrieving data from the list with new issues.
def create_alert_object(new_issue):
    sourceRef = str(uuid.uuid4())[0:6]
    data = ''.join(new_issue['data'])
    alert = Alert(title= 'Security Scorecard alert: {}'.format(new_issue['title']),
        tlp=3,
        tags=['security_scorecard', 'issue_type: {}'.format(new_issue['issue_type']), new_issue['factor'], 'domain: {}'.format(new_issue['domain'])],
        description='#### ' + new_issue['short_description'] + '\n\n' + data,
        type='security-scorecard',
        severity=3 if new_issue['severity'] == 'high' else 2,
        source='scorecard_to_thehive',
        artifacts=new_issue['artifacts'],
        sourceRef=sourceRef
    )
    return alert

# Check if ID already in issue file. Added because Scorecard "backports" the dates of the new issues.
def id_in_file(id):
    with open('/home/csirt/thehive_alert/issue_id_scorecard.txt', 'a+') as file:
        file.seek(0)
        if str(id) in file.read():
            return True
        file.write(str(id) + '\n')
        return False

######################################################################################################
#                                            MAIN                                                   #
######################################################################################################
url = "https://api.securityscorecard.io/companies/sandvik.com/history/events/"
url_meta = "https://api.securityscorecard.io/metadata/issue-types/"
api = TheHiveApi('http://127.0.0.1:9000', 'XXX')

headers = {
    "Accept": "application/json; charset=utf-8",
    "Authorization": "Token XXX"
}

new_issues_list = []
# Set boolean if file not already exisits to prevent spamming of hundreds of issues to TheHive, if the issue-id-list somehow got lost.
file_exists = os.path.exists('/home/csirt/thehive_alert/issue_id_scorecard.txt')

# Check for new issues
response_new_issues = get_new_issues(url)

# Only parse the active issues with the severity high or medium. Excluding the "patching_cadence"-issues as there are not relevant issues for us for now. 
for new_issue in response_new_issues['entries']:
        if(new_issue['event_type'] == 'issues' and new_issue['group_status'] == 'active' and (new_issue['severity'] == 'high' or new_issue['severity'] == 'medium') and new_issue['factor'] != 'patching_cadence'):
            if(not id_in_file(new_issue['id'])):
                response_issue_info = get_data_about_new_issues(new_issue['detail_url'])
                parse_new_issue_data(new_issue, response_issue_info)

# End program if no new issues
if(not new_issues_list):
    print('No new issues, exit script..')
    exit()

# Only send alerts to TheHive if the issue-id-file already existed before the run. Otherwise, it is the first run or the file has somehow got lost.
# Don't want to spam TheHive with hundreds of issues. Remove the if-statement if you want the opposite.
if(file_exists):
    for new_issue in new_issues_list:
        # Create the alert object
        alert = create_alert_object(new_issue)

        # Create the alert and send to TheHive
        try:
            response = api.create_alert(alert)
            # Print the JSON response
            print(json.dumps(response.json(), indent=4, sort_keys=True))

        except Exception as e:
            raise SystemExit(e)
