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
from typing import Optional, Dict, List, Any, Sequence, Union, Iterable
from packaging import version
from pathlib import Path

log_format = (
    "%(asctime)s - [%(module)s::%(funcName)s::%(lineno)d] - %(levelname)s - %(message)s"
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - [%(module)s::%(funcName)s::%(lineno)d] - %(levelname)s - %(message)s",
)

logging.captureWarnings(True)


class Wazuh_Importer(object):
    """API exporter for Wazuh."""

    DEFAULT_HITS_PER_FILE = 100000
    VALID_OUTPUT_MODES = {"single", "split"}

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
        output_mode: str = "single",
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
            output_mode (str): Output mode: "single" (default) or "split".
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
        self.output_mode: str = output_mode.strip().lower()
        self.wazuh_api_version: Optional[str] = None
        self.opensearch_client: Optional[OpenSearch] = None

        if self.output_mode not in self.VALID_OUTPUT_MODES:
            self.logger.warning(
                f"Unknown output_mode '{output_mode}'. Falling back to 'single'."
            )
            self.output_mode = "single"

        if disable_insecure_request_warnings:
            self._disable_insecure_request_warnings()
        self.authenticate()
        self._get_api_version()

        api_version = self.wazuh_api_version or "0.0.0"
        if (
            OPENSEARCH_USERNAME
            and OPENSEARCH_PASSWORD
            and version.parse(api_version) >= version.parse("4.8.0")
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
                affected_items = data.get("data", {}).get("affected_items")
                api_version = None

                if isinstance(affected_items, list) and len(affected_items) > 0:
                    first_item = affected_items[0]
                    if isinstance(first_item, dict):
                        api_version = first_item.get("version")

                if api_version is None:
                    self.logger.error(
                        f"Failed to parse Wazuh API version from response: {data}"
                    )
                    return None

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

    def _clear_the_scroll_index(self, scroll_id: str) -> None:
        try:
            self.logger.info("Clearing scroll index")
            self.opensearch_client.clear_scroll(scroll_id=scroll_id)
        except AuthenticationException:
            self.logger.error("Received 401 Unauthorized.")
        except RequestError as re:
            self.logger.error(f"Received 400: {re}")
        except Exception as e:
            self.logger.error(
                f"Unexpected error while clearing scroll '{scroll_id}': {e}"
            )

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

        if self.opensearch_client is None:
            self.logger.error("OpenSearch client is not configured.")
            return {}

        response: Dict[str, Any] = {}

        try:
            response = self.get_vulnerabilities_for_group_of_agents_4_8_plus_page(
                agent_ids=agent_ids, scroll_id=None
            )
        except AuthenticationException:
            self.logger.error("Received 401 Unauthorized.")
        except RequestError as re:
            self.logger.error(f"Received 400: {re}")
        except Exception as e:
            self.logger.error(
                f"Unexpected error while fetching group '{agent_ids}': {e}"
            )

        total_hits = response["hits"]["total"]["value"]
        scroll_id: str = response["_scroll_id"]

        if total_hits <= 10000:
            self._clear_the_scroll_index(scroll_id)
            return response

        self.logger.info(f"Total hits - {total_hits}. Start scrolling...")

        while True:
            self.logger.info("Scrolling next 10000 hits")
            try:
                scroll_response = (
                    self.get_vulnerabilities_for_group_of_agents_4_8_plus_page(
                        agent_ids=agent_ids, scroll_id=scroll_id
                    )
                )
                scroll_id = scroll_response["_scroll_id"]
                hits = scroll_response["hits"]["hits"]
                if not hits:
                    self.logger.info("Ending scrolling")
                    break
                response["hits"]["hits"].extend(hits)
            except AuthenticationException:
                self.logger.error("Received 401 Unauthorized.")
                break
            except RequestError as re:
                self.logger.error(f"Received 400: {re}")
                break
            except Exception as e:
                self.logger.error(
                    f"Unexpected error while fetching group '{agent_ids}': {e}"
                )
                break

        self._clear_the_scroll_index(scroll_id)

        return response

    def get_vulnerabilities_for_group_of_agents_4_8_plus_page(
        self, agent_ids: Sequence[str], scroll_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Retrieve one page of vulnerabilities (initial or scroll).

        Args:
            agent_ids (list[str]): Wazuh agent IDs.
            scroll_id (str | None): Scroll ID for subsequent requests.

        Returns:
            dict: OpenSearch response payload, or an empty dict on failure.
        """
        if self.opensearch_client is None:
            self.logger.error("OpenSearch client is not configured.")
            return {}

        if scroll_id:
            return self._opensearch_scroll_next(scroll_id)

        return self._opensearch_search_initial(agent_ids)

    def _opensearch_search_initial(self, agent_ids: Sequence[str]) -> Dict[str, Any]:
        if self.opensearch_client is None:
            raise RuntimeError("OpenSearch client is not configured.")
        query = {
            "query": {
                "bool": {
                    "must": [{"terms": {"agent.id": agent_ids}}],
                    "should": [
                        {"match": {"vulnerability.severity": "Critical"}},
                        {"match": {"vulnerability.severity": "High"}},
                        {"match": {"vulnerability.severity": "Medium"}},
                        {"match": {"vulnerability.severity": "Low"}},
                    ],
                }
            }
        }
        return self.opensearch_client.search(
            body=query, index=self.elasticsearch_index, scroll="1m", size=10000
        )

    def _opensearch_scroll_next(self, scroll_id: str) -> Dict[str, Any]:
        if self.opensearch_client is None:
            raise RuntimeError("OpenSearch client is not configured.")
        return self.opensearch_client.scroll(scroll_id=scroll_id, scroll="1m")

    def _chunked(self, items: Sequence[Any], chunk_size: int) -> Iterable[List[Any]]:
        for i in range(0, len(items), chunk_size):
            yield list(items[i : i + chunk_size])

    def _chunk_output_path(self, output_file: Path, part_index: int) -> Path:
        stem = output_file.stem
        suffix = output_file.suffix
        return output_file.with_name(f"{stem}_{part_index:04d}{suffix}")

    def _write_json_file(self, output_file: Path, payload: Dict[str, Any]) -> None:
        try:
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)
            self.logger.info(f"Wazuh vulnerabilities saved to: {output_file}")
        except OSError as e:
            self.logger.error(f"Failed to write results to {output_file}: {e}")

    def _write_split_findings(
        self,
        output_file: Path,
        vulnerabilities_list: Dict[str, Any],
        api_version: str,
    ) -> List[Path]:
        output_files: List[Path] = []

        if version.parse(api_version) < version.parse("4.8.0"):
            data_section = vulnerabilities_list.get("data", {})
            affected_items = data_section.get("affected_items", [])
            if not isinstance(affected_items, list):
                affected_items = []
            total_items = data_section.get("total_affected_items", len(affected_items))

            for index, chunk in enumerate(
                self._chunked(affected_items, self.DEFAULT_HITS_PER_FILE), start=1
            ):
                payload = {
                    "data": {
                        "affected_items": chunk,
                        "total_affected_items": total_items,
                    }
                }
                chunk_file = self._chunk_output_path(output_file, index)
                self._write_json_file(chunk_file, payload)
                output_files.append(chunk_file)

            if not output_files:
                chunk_file = self._chunk_output_path(output_file, 1)
                payload = {
                    "data": {
                        "affected_items": [],
                        "total_affected_items": total_items,
                    }
                }
                self._write_json_file(chunk_file, payload)
                output_files.append(chunk_file)

            return output_files

        if not vulnerabilities_list or "hits" not in vulnerabilities_list:
            self._write_json_file(output_file, vulnerabilities_list)
            return [output_file]

        hits_section = vulnerabilities_list.get("hits", {})
        hits = hits_section.get("hits", [])
        if not isinstance(hits, list):
            hits = []

        base_payload = {
            key: value for key, value in vulnerabilities_list.items() if key != "hits"
        }
        base_hits = {key: value for key, value in hits_section.items() if key != "hits"}

        for index, chunk in enumerate(
            self._chunked(hits, self.DEFAULT_HITS_PER_FILE), start=1
        ):
            payload = dict(base_payload)
            payload_hits = dict(base_hits)
            payload_hits["hits"] = chunk
            payload["hits"] = payload_hits
            chunk_file = self._chunk_output_path(output_file, index)
            self._write_json_file(chunk_file, payload)
            output_files.append(chunk_file)

        if not output_files:
            chunk_file = self._chunk_output_path(output_file, 1)
            self._write_json_file(chunk_file, vulnerabilities_list)
            output_files.append(chunk_file)

        return output_files

    def _write_split_findings_streaming_4_8_plus(
        self, output_file: Path, agent_ids: Sequence[str]
    ) -> List[Path]:
        output_files: List[Path] = []
        buffer_hits: List[Any] = []
        base_payload: Optional[Dict[str, Any]] = None
        base_hits: Optional[Dict[str, Any]] = None
        part_index = 1
        scroll_id: Optional[str] = None
        latest_scroll_id: Optional[str] = None
        total_hits: Optional[int] = None
        is_first = True

        try:
            while True:
                try:
                    response = (
                        self.get_vulnerabilities_for_group_of_agents_4_8_plus_page(
                            agent_ids=agent_ids, scroll_id=scroll_id
                        )
                    )
                except AuthenticationException:
                    self.logger.error("Received 401 Unauthorized.")
                    break
                except RequestError as re:
                    self.logger.error(f"Received 400: {re}")
                    break
                except Exception as e:
                    self.logger.error(
                        f"Unexpected error while fetching group '{agent_ids}': {e}"
                    )
                    break
                if not response:
                    break

                latest_scroll_id = response.get("_scroll_id", latest_scroll_id)
                hits_section = response.get("hits", {})
                hits = hits_section.get("hits", [])
                if not isinstance(hits, list):
                    hits = []

                if is_first:
                    base_payload = {
                        key: value for key, value in response.items() if key != "hits"
                    }
                    base_hits = {
                        key: value
                        for key, value in hits_section.items()
                        if key != "hits"
                    }
                    total_hits = (hits_section.get("total", {}) or {}).get("value")
                    if total_hits is not None and len(hits) < total_hits:
                        self.logger.info(
                            f"Total hits - {total_hits}. Start scrolling..."
                        )

                if not hits:
                    break

                buffer_hits.extend(hits)
                while len(buffer_hits) >= self.DEFAULT_HITS_PER_FILE:
                    chunk = buffer_hits[: self.DEFAULT_HITS_PER_FILE]
                    buffer_hits = buffer_hits[self.DEFAULT_HITS_PER_FILE :]
                    payload = dict(base_payload or {})
                    payload_hits = dict(base_hits or {})
                    payload_hits["hits"] = chunk
                    payload["hits"] = payload_hits
                    chunk_file = self._chunk_output_path(output_file, part_index)
                    self._write_json_file(chunk_file, payload)
                    output_files.append(chunk_file)
                    part_index += 1

                if is_first and total_hits is not None and len(hits) >= total_hits:
                    scroll_id = latest_scroll_id
                    break

                scroll_id = latest_scroll_id
                is_first = False
        finally:
            if latest_scroll_id and self.opensearch_client is not None:
                try:
                    self.logger.info("Clearing scroll")
                    self.opensearch_client.clear_scroll(scroll_id=latest_scroll_id)
                except AuthenticationException:
                    self.logger.error("Received 401 Unauthorized.")
                except RequestError as re:
                    self.logger.error(f"Received 400: {re}")
                except Exception as e:
                    self.logger.error(
                        f"Unexpected error while clearing scroll '{latest_scroll_id}': {e}"
                    )

        if base_payload is None:
            self._write_json_file(output_file, {})
            return [output_file]

        if buffer_hits or not output_files:
            payload = dict(base_payload or {})
            payload_hits = dict(base_hits or {})
            payload_hits["hits"] = buffer_hits
            payload["hits"] = payload_hits
            chunk_file = self._chunk_output_path(output_file, part_index)
            self._write_json_file(chunk_file, payload)
            output_files.append(chunk_file)

        return output_files

    def get_findings(
        self, group: str, filedestination: str, filename: str = "wazuh.json"
    ) -> Union[Path, List[Path]]:
        """
        Retrieve vulnerabilities for all agents in a group and save to JSON.

        Args:
            group (str): Wazuh group name.
            filedestination (str): Directory where the JSON file will be saved.
            filename (str): JSON filename.

        Returns:
            Path | list[Path]: Path(s) to the saved JSON file(s).

        Raises:
            OSError: If the destination directory cannot be created.

        Notes:
            When output_mode is "split", results are written in chunks of 100000 hits.
        """
        Path(filedestination).mkdir(parents=True, exist_ok=True)
        output_file = Path(filedestination) / filename
        group_agents = self.get_agents_in_group(group)

        api_version = self.wazuh_api_version or "0.0.0"
        vulnerabilities_list: Dict[str, Any]
        if version.parse(api_version) < version.parse("4.8.0"):
            vulnerabilities_list = {"data": {"affected_items": []}}
            vulncount: int = 0

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
            agent_ids: List[str] = []
            for agent in group_agents:
                agent_id = agent.get("id")
                if isinstance(agent_id, str):
                    agent_ids.append(agent_id)
            if self.output_mode == "split":
                return self._write_split_findings_streaming_4_8_plus(
                    output_file=output_file, agent_ids=agent_ids
                )
            vulnerabilities_list = (
                self.get_vulnerabilities_for_group_of_agents_4_8_plus(
                    agent_ids=agent_ids
                )
            )

        if self.output_mode == "split":
            return self._write_split_findings(
                output_file=output_file,
                vulnerabilities_list=vulnerabilities_list,
                api_version=api_version,
            )

        self._write_json_file(output_file, vulnerabilities_list)

        return output_file
