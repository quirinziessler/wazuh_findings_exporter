# Origin of this script: https://github.com/DefectDojo/django-DefectDojo/pull/8746


import logging
import requests
import urllib3
import json
import warnings
from opensearchpy.exceptions import AuthenticationException, RequestError
from opensearchpy import OpenSearch
from requests.auth import HTTPBasicAuth
from requests.exceptions import (
    ConnectTimeout,
    ReadTimeout,
    ConnectionError,
    RequestException,
)
from typing import Optional, Dict, List, Any, Sequence
from packaging import version
from pathlib import Path

# TODO: Implement unit tests for new methods, especially for OpenSearch-based methods and API version >= 4.8 functionality.
# TODO: Update package to version 2.0 with major refactoring and new features while keeping Wazuh API 4.7 compatibility

log_format = (
    "%(asctime)s - [%(module)s::%(funcName)s::%(lineno)d] - %(levelname)s - %(message)s"
)

logging.captureWarnings(True)
logger = logging.getLogger(__name__)


class Wazuh_Importer(object):
    """API exporter for Wazuh."""

    def __init__(
        self,
        BASE_URL: str,
        USERNAME: str,
        PASSWORD: str,
        OPENSEARCH_USERNAME: str = "",
        OPENSEARCH_PASSWORD: str = "",
        OPENSEARCH_HOST: str = "",
        OPENSEARCH_PORT: int = 9200,
        verify: bool = False,
        timeout: float = 10,
        elasticsearch_index: str = "wazuh-states-vulnerabilities-*",
        logger: Optional[logging.Logger] = None,
        disable_insecure_request_warnings: bool = True,
    ) -> None:
        """
        Initialize the Wazuh importer and optionally the OpenSearch client.

        Args:
            BASE_URL (str): Base URL of the Wazuh API endpoint.
            USERNAME (str): Wazuh username.
            PASSWORD (str): Wazuh password.
            OPENSEARCH_USERNAME (str): OpenSearch username (Wazuh 4.8+).
            OPENSEARCH_PASSWORD (str): OpenSearch password (Wazuh 4.8+).
            OPENSEARCH_HOST (str): OpenSearch host.
            OPENSEARCH_PORT (int): OpenSearch port.
            verify (bool): Enable or disable SSL certificate verification.
            timeout (int | float): Request timeout in seconds.
            elasticsearch_index (str): OpenSearch index pattern for vulnerabilities.
            logger (logging.Logger | None): Logger instance to use.
            disable_insecure_request_warnings (bool): Suppress insecure request warnings.

        Returns:
            None.

        Raises:
            Exception: Propagates any unexpected error while initializing the OpenSearch
                client.
        """

        self.logger: logging.Logger = logger or logging.getLogger(__name__)
        self.BASE_URL: str = BASE_URL
        self.AUTH_URL: str = f"{BASE_URL}/security/user/authenticate?raw=true"
        self.USERNAME: str = USERNAME
        self.PASSWORD: str = PASSWORD
        self.OPENSEARCH_USERNAME: str = OPENSEARCH_USERNAME
        self.OPENSEARCH_PASSWORD: str = OPENSEARCH_PASSWORD
        self.OPENSEARCH_HOST: str = OPENSEARCH_HOST
        self.OPENSEARCH_PORT: int = OPENSEARCH_PORT
        self.HEADERS: Dict[str, str] = {}
        self.verify: bool = verify
        self.timeout: float = timeout
        self.elasticsearch_index: str = elasticsearch_index
        self.wazuh_api_version: Optional[str] = None
        self.opensearch_client: Optional[OpenSearch] = None

        if disable_insecure_request_warnings:
            self._disable_insecure_request_warnings()
        self.authenticate()
        self._get_api_version()

        if (
            OPENSEARCH_USERNAME
            and OPENSEARCH_PASSWORD
            and version.parse(self.wazuh_api_version) >= version.parse("4.8.0")
        ):
            self.opensearch_client = OpenSearch(
                hosts=[{"host": self.OPENSEARCH_HOST, "port": self.OPENSEARCH_PORT}],
                use_ssl=True,
                http_auth=(self.OPENSEARCH_USERNAME, self.OPENSEARCH_PASSWORD),
                verify_certs=self.verify,
            )

    def _disable_insecure_request_warnings(self) -> None:
        """
        Suppress warnings about insecure HTTPS requests.

        Args:
            None.

        Returns:
            None.

        Raises:
            None.
        """
        warnings.filterwarnings(
            "ignore",
            category=UserWarning,
            module="opensearchpy.connection.http_urllib3",
        )
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def _get_api_version(self) -> Optional[str]:
        """
        Retrieve Wazuh API version.

        Args:
            None.

        Returns:
            str | None: API version string if successful, otherwise None.

        Raises:
            None. Errors are logged and the method returns None on failure.
        """
        endpoint = f"{self.BASE_URL}/manager/info"

        try:
            response = requests.get(
                endpoint, headers=self.HEADERS, verify=self.verify, timeout=self.timeout
            )

            if response.status_code == 401:
                self.logger.warning(
                    "Received 401 Unauthorized. Re-authenticating and retrying request"
                )
                self.authenticate()
                response = requests.get(
                    endpoint,
                    headers=self.HEADERS,
                    verify=self.verify,
                    timeout=self.timeout,
                )

            if response.status_code == 200:
                data = response.json()
                api_version = (
                    data.get("data", {})
                    .get("affected_items", [])[0]
                    .get("version", None)
                )
                self.logger.info(f"Wazuh API version: {api_version}")
                self.wazuh_api_version = api_version
                return api_version
            else:
                self.logger.error(
                    f"Failed to get API version. "
                    f"Status code: {response.status_code}, Detail: {response.text}"
                )
                return None

        except (ConnectTimeout, ReadTimeout, ConnectionError, RequestException) as e:
            self.logger.error(f"Request error while fetching API version: {e}")
        except Exception as e:
            self.logger.error(f"Unexpected error while fetching API version: {e}")

        return None

    def authenticate(self) -> bool:
        """
        Authenticate against the Wazuh API and set the Bearer token.

        Args:
            None.

        Returns:
            bool: True if authentication succeeded, False otherwise.

        Raises:
            None. Errors are logged and the method returns False on failure.
        """
        try:
            response = requests.get(
                self.AUTH_URL,
                auth=HTTPBasicAuth(self.USERNAME, self.PASSWORD),
                verify=self.verify,
                timeout=self.timeout,
            )

            if response.status_code == 200:
                token = response.text.strip()
                self.HEADERS["Authorization"] = f"Bearer {token}"
                self.logger.info("Successfully authenticated against Wazuh API.")
                return True
            else:
                self.logger.error(
                    f"Authentication failed. "
                    f"Status code: {response.status_code}, Detail: {response.text}"
                )
                return False

        except ConnectTimeout as e:
            self.logger.error(f"Connection timed out during authentication: {e}")
        except ReadTimeout as e:
            self.logger.error(f"Read timed out during authentication: {e}")
        except ConnectionError as e:
            self.logger.error(f"Connection error during authentication: {e}")
        except RequestException as e:
            self.logger.error(f"Request failed during authentication: {e}")
        except Exception as e:
            self.logger.error(f"Unexpected error during authentication: {e}")

        return False

    def get_agents_in_group(self, group: str) -> List[Dict[str, Any]]:
        """
        Retrieve all agents belonging to a specific group.

        Args:
            group (str): Wazuh group name.

        Returns:
            list: List of agent objects, or [] if request fails.

        Raises:
            None. Errors are logged and the method returns [] on failure.
        """
        endpoint = f"{self.BASE_URL}/groups/{group}/agents"
        params = {"limit": 100000}

        try:
            response = requests.get(
                endpoint,
                headers=self.HEADERS,
                verify=self.verify,
                timeout=self.timeout,
                params=params,
            )

            # Retry once if token expired
            if response.status_code == 401:
                self.logger.warning(
                    "Received 401 Unauthorized. Re-authenticating and retrying request"
                )
                self.authenticate()
                response = requests.get(
                    endpoint,
                    headers=self.HEADERS,
                    verify=self.verify,
                    timeout=self.timeout,
                    params=params,
                )

            if response.status_code == 200:
                self.logger.info(f"Successfully retrieved agents for group '{group}'")
                return response.json().get("data", {}).get("affected_items", [])

            self.logger.error(
                f"Failed to retrieve agents for group '{group}'. "
                f"Status code: {response.status_code}, Detail: {response.text}"
            )
            return []

        except ConnectTimeout as e:
            self.logger.error(
                f"Connection timed out while fetching agents for group '{group}': {e}"
            )
        except ReadTimeout as e:
            self.logger.error(
                f"Read timed out while fetching agents for group '{group}': {e}"
            )
        except ConnectionError as e:
            self.logger.error(
                f"Connection error while fetching agents for group '{group}': {e}"
            )
        except RequestException as e:
            self.logger.error(
                f"Unexpected request error while fetching agents for group '{group}': {e}"
            )
        except Exception as e:
            self.logger.error(
                f"Unexpected error while fetching agents for group '{group}': {e}"
            )

        return []

    def get_vulnerabilities_for_agent(self, agent_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve vulnerabilities for a specific agent (Wazuh API < 4.8).

        Args:
            agent_id (str): Wazuh agent ID.

        Returns:
            dict | None: Vulnerability data, or None if request fails.

        Raises:
            None. Errors are logged and the method returns None on failure.
        """
        endpoint = f"{self.BASE_URL}/vulnerability/{agent_id}"
        params = {"limit": 100000}

        try:
            response = requests.get(
                endpoint,
                headers=self.HEADERS,
                verify=self.verify,
                timeout=self.timeout,
                params=params,
            )

            # Retry once if token expired
            if response.status_code == 401:
                self.logger.warning(
                    "Received 401 Unauthorized. Re-authenticating and retrying request"
                )
                self.authenticate()
                response = requests.get(
                    endpoint,
                    headers=self.HEADERS,
                    verify=self.verify,
                    timeout=self.timeout,
                    params=params,
                )

            if response.status_code == 200:
                self.logger.info("Successfully retrieved vulnerabilities for agents")
                return response.json()
            elif response.status_code == 400:
                self.logger.info(f"No vulnerabilities found for agent '{agent_id}'")
                return None
            elif response.status_code == 404:
                self.logger.warning(
                    f"Endpoint '/vulnerability/{agent_id}' returned 404. "
                    f"This may happen if your Wazuh API version >= 4.8. "
                    f"Please use 'get_vulnerabilities_for_agent_4_8_plus' instead."
                )
                return None
            else:
                self.logger.error(
                    f"Failed to retrieve vulnerabilities for agent '{agent_id}'. "
                    f"Status code: {response.status_code}, Detail: {response.text}"
                )
                return None

        except ConnectTimeout as e:
            self.logger.error(
                f"Connection timed out while fetching vulnerabilities for agent '{agent_id}': {e}"
            )
        except ReadTimeout as e:
            self.logger.error(
                f"Read timed out while fetching vulnerabilities for agent '{agent_id}': {e}"
            )
        except ConnectionError as e:
            self.logger.error(
                f"Connection error while fetching vulnerabilities for agent '{agent_id}': {e}"
            )
        except RequestException as e:
            self.logger.error(
                f"Unexpected request error while fetching vulnerabilities for agent '{agent_id}': {e}"
            )
        except Exception as e:
            self.logger.error(
                f"Unexpected error while fetching vulnerabilities for agent '{agent_id}': {e}"
            )

        return None

    def get_vulnerabilities_for_group_of_agents_4_8_plus(
        self, agent_ids: Sequence[str]
    ) -> Dict[str, Any]:
        """
        Retrieve vulnerabilities for a group of agents (Wazuh API >= 4.8).

        Args:
            agent_ids (list[str]): Wazuh agent IDs.

        Returns:
            dict: OpenSearch response payload, or an empty dict on failure.

        Raises:
            None. Errors are logged and the method returns {} on failure.
        """

        query = {
            "query": {
                "bool": {
                    "must": [{"terms": {"agent.id": agent_ids}}],
                    "should": [
                        {"match": {"vulnerability.severity": "Critical"}},
                        {"match": {"vulnerability.severity": "High"}},
                        {"match": {"vulnerability.severity": "Medium"}},
                        {"match": {"vulnerability.severity": "Low"}},
                        {"match": {"vulnerability.severity": ""}},
                    ],
                    "minimum_should_match": 1,
                }
            }
        }
        if self.opensearch_client is None:
            self.logger.error("OpenSearch client is not configured.")
            return {}

        response: Dict[str, Any] = {}

        try:
            response = self.opensearch_client.search(
                body=query, index=self.elasticsearch_index
            )
        except AuthenticationException:
            self.logger.error("Received 401 Unauthorized.")
        except RequestError as re:
            self.logger.error(f"Received 400: {re}")
        except Exception as e:
            self.logger.error(
                f"Unexpected error while fetching group '{agent_ids}': {e}"
            )

        return response

    def get_findings(
        self, group: str, filedestination: str, filename: str = "wazuh.json"
    ) -> Path:
        """
        Retrieve vulnerabilities for all agents in a group and save to JSON.

        Args:
            group (str): Wazuh group name.
            filedestination (str): Directory where the JSON file will be saved.
            filename (str): JSON filename.

        Returns:
            Path: Path to the saved JSON file.

        Raises:
            OSError: If the destination directory cannot be created.
        """
        Path(filedestination).mkdir(parents=True, exist_ok=True)
        output_file = Path(filedestination) / filename
        group_agents = self.get_agents_in_group(group)

        if version.parse(self.wazuh_api_version) < version.parse("4.8.0"):
            vulnerabilities_list = {"data": {"affected_items": []}}
            vulncount = 0

            # Build lookup tables for IPs and names
            group_agents_data = {agent["id"]: agent.get("ip") for agent in group_agents}
            group_agents_name = {
                agent["id"]: agent.get("name") for agent in group_agents
            }

            # Iterate over agents
            for agent_id in group_agents_data:
                vulnerabilities = self.get_vulnerabilities_for_agent(agent_id)
                if not vulnerabilities:
                    continue

                filtered_vulnerabilities = []
                for vuln in vulnerabilities.get("data", {}).get("affected_items", []):
                    if vuln.get("condition") != "Package unfixed":
                        vuln["agent_ip"] = group_agents_data[agent_id]
                        vuln["agent_name"] = group_agents_name[agent_id]
                        filtered_vulnerabilities.append(vuln)

                if filtered_vulnerabilities:
                    vulnerabilities_list["data"]["affected_items"].extend(
                        filtered_vulnerabilities
                    )
                    vulncount += len(filtered_vulnerabilities)

            vulnerabilities_list["data"]["total_affected_items"] = vulncount

        else:
            agent_ids = [agent.get("id") for agent in group_agents]
            vulnerabilities_list = (
                self.get_vulnerabilities_for_group_of_agents_4_8_plus(
                    agent_ids=agent_ids
                )
            )

        # Save results
        try:
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(vulnerabilities_list, f, indent=2)
            self.logger.info(f"Wazuh vulnerabilities saved to: {output_file}")
        except OSError as e:
            self.logger.error(f"Failed to write results to {output_file}: {e}")

        return output_file
