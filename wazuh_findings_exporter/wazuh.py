# Origin of this script: https://github.com/DefectDojo/django-DefectDojo/pull/8746

import requests
from requests.auth import HTTPBasicAuth
import json
import urllib3

# Suppress InsecureRequestWarning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Main function
class Wazuh_Importer(object):
    '''An API exporter for Wazuh.'''

    # Basic authentication creds
    def __init__(self, BASE_URL, USERNAME, PASSWORD):
        '''Initializes the requirements for the export
        
        :param BASE_URL: The Base URL of the Wazuh API endpoint.
        :param USERNAME: Username of the Wazuh User.
        :param PASSWORD: Password of the Wazuh User.
        '''

        self.BASE_URL = BASE_URL
        self.AUTH_URL = f"{BASE_URL}/security/user/authenticate?raw=true"
        self.USERNAME = USERNAME
        self.PASSWORD = PASSWORD
        self.HEADERS = {}
        self.authenticate()
        
    # Authenticate and set token
    def authenticate(self):
        response = requests.get(
            self.AUTH_URL, auth=HTTPBasicAuth(self.USERNAME, self.PASSWORD), verify=False
        )
        if response.status_code == 200:
            token = response.text
            self.HEADERS["Authorization"] = f"Bearer {token}"
        else:
            raise ValueError(
                f"Failed to authenticate. Status code: {response.status_code}, Detail: {response.text}"
            )
    
    # Retrieve agents for a specific group
    def get_agents_in_group(self, group):
        endpoint = f"{self.BASE_URL}/groups/{group}/agents"
        response = requests.get(endpoint, headers=self.HEADERS, verify=False, params={"limit":100000}) #nosemgrep
        if response.status_code == 401: #In case the auth times out, need to re-authenticate
            self.authenticate()
            response = requests.get(endpoint, headers=self.HEADERS, verify=False, params={"limit":100000}) #nosemgrep
        if response.status_code == 200:
            return response.json()["data"]["affected_items"]
        else:
            print(
                f"Failed to retrieve agents for group {group}. Status code: {response.status_code}, Detail: {response.text}"
            )
            return []

    # Retrieve vulnerabilities for a specific agent
    def get_vulnerabilities_for_agent(self, agent_id):
        endpoint = f"{self.BASE_URL}/vulnerability/{agent_id}"
        response = requests.get(endpoint, headers=self.HEADERS, verify=False, params={"limit":100000}) #nosemgrep
        if response.status_code == 401:
            self.authenticate()
            response = requests.get(endpoint, headers=self.HEADERS, verify=False, params={"limit":100000}) #nosemgrep
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

    def get_findings(self, group, filedestination):
        '''Retrieves the findings and saves it to a json file.

        :param group: Group of the Wazuh Clients.
        :param filedestination: Destination where to save the file to.
        '''
        vulnerabilities_list = {
            "data": {
                "affected_items": []
            }
        }

        group_agents = self.get_agents_in_group(group)

        # Extract the agent IDs and IPs from the response for each group
        group_agents_data = {agent["id"]: agent["ip"] for agent in group_agents}
        group_agents_name = {agent["id"]: agent["name"] for agent in group_agents}

        # Find the intersection of the two sets
        common_ids = set(group_agents_data.keys())

        # Loop through each agent_id and get its vulnerabilities
        vulncount = 0
        for agent_id in common_ids:
            vulnerabilities = self.get_vulnerabilities_for_agent(agent_id)
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
                        vulncount += 1
                if filtered_vulnerabilities != []:
                    vulnerabilities_list["data"]["affected_items"] += filtered_vulnerabilities

        vulnerabilities_list["data"]["total_affected_items"] = vulncount

            # Write the filtered vulnerabilities to a JSON file
        with open(filedestination + "wazuh.json", "wt", encoding="utf-8") as f:
            json.dump(vulnerabilities_list,f,indent=2)
        
        print("Wazuh vulnerabilities saved to: " + filedestination)
