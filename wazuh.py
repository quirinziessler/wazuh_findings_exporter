# Origin of this script: https://github.com/DefectDojo/django-DefectDojo/pull/8746

import requests
from requests.auth import HTTPBasicAuth
import json
import urllib3
import os
import dotenv
dotenv.load_dotenv()

# Suppress InsecureRequestWarning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Wazuh
BASE_URL = os.environ.get("WAZUH-URL")
AUTH_URL = f"{BASE_URL}/security/user/authenticate?raw=true"
HEADERS = {}

# Basic authentication creds
USERNAME = os.environ.get("WAZUH-USER")
PASSWORD = os.environ.get("WAZUH-PW")

# Authenticate and set token
def authenticate():
    response = requests.get(
        AUTH_URL, auth=HTTPBasicAuth(USERNAME, PASSWORD), verify=False
    )
    if response.status_code == 200:
        token = response.text
        HEADERS["Authorization"] = f"Bearer {token}"
    else:
        raise ValueError(
            f"Failed to authenticate. Status code: {response.status_code}, Detail: {response.text}"
        )


# Retrieve agents for a specific group
def get_agents_in_group(group_name):
    endpoint = f"{BASE_URL}/groups/{group_name}/agents"
    response = requests.get(endpoint, headers=HEADERS, verify=False, params={"limit":100000})
    if response.status_code == 401: #In case the auth times out, need to re-authenticate
        authenticate()
        response = requests.get(endpoint, headers=HEADERS, verify=False, params={"limit":100000})
    if response.status_code == 200:
        return response.json()["data"]["affected_items"]
    else:
        print(
            f"Failed to retrieve agents for group {group_name}. Status code: {response.status_code}, Detail: {response.text}"
        )
        return []


# Retrieve vulnerabilities for a specific agent
def get_vulnerabilities_for_agent(agent_id):
    endpoint = f"{BASE_URL}/vulnerability/{agent_id}"
    response = requests.get(endpoint, headers=HEADERS, verify=False, params={"limit":100000})
    if response.status_code == 401:
        authenticate()
        response = requests.get(endpoint, headers=HEADERS, verify=False, params={"limit":100000})
    if response.status_code == 200:
        return response.json()
    elif response.status_code == 400:
        #no findings
        return None
    else:
        print(
            f"Failed to retrieve vulnerabilities for agent {agent_id}. Status code: {response.status_code}, Detail: {response.text}"
        )
        return None


# Main function
class Wazuh_Importer(object):
    def __init__(self):
        authenticate()

    def get_findings(self, group, filedestination):
        vulnerabilities_list = []

        group_agents = get_agents_in_group(group)

        # Extract the agent IDs and IPs from the response for each group
        group_agents_data = {agent["id"]: agent["ip"] for agent in group_agents}
        group_agents_name = {agent["id"]: agent["name"] for agent in group_agents}

        # Find the intersection of the two sets
        common_ids = set(group_agents_data.keys())

        # Loop through each agent_id and get its vulnerabilities
        for agent_id in common_ids:
            vulnerabilities = get_vulnerabilities_for_agent(agent_id)
            if vulnerabilities:
                filtered_vulnerabilities = []
                # Extend the vulnerabilities with agent_ip field
                for vulnerability in vulnerabilities.get("data", {}).get(
                    "affected_items", []
                ):
                    #Skip the vulnerability if its condition is "Package unfixed"
                    if vulnerability.get("condition") != "Package unfixed":
                        vulnerability["agent_ip"] = group_agents_data[agent_id]
                        vulnerability["agent_name"] = group_agents_name[agent_id]
                        filtered_vulnerabilities.append(vulnerability)
                if filtered_vulnerabilities != []:
                    vulnerabilities["data"]["affected_items"] = filtered_vulnerabilities
                    vulnerabilities_list.append(vulnerabilities)

            # Write the filtered vulnerabilities to a JSON file
        with open(filedestination + "wazuh.json", "wt", encoding="utf-8") as f:
            json.dump(vulnerabilities_list,f,indent=2)
        
        print("Wazuh vulnerabilities saved to: " + filedestination)
