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
        """
        warnings.filterwarnings(
            "ignore",
            category=UserWarning,
            module="opensearchpy.connection.http_urllib3",
        )
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def _get_api_version(self) -> Optional[str]:
        """
        Retrieve the Wazuh API version from the manager endpoint.

        Returns:
            str | None: API version string if successfully retrieved, otherwise None.
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
        Authenticate against the Wazuh API using basic auth and store
        the Bearer token for subsequent requests.

        Returns:
            bool: True if authentication succeeds, False otherwise.
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
        Retrieve vulnerabilities for a specific agent using the Wazuh API
        (Wazuh versions < 4.8).

        Args:
            agent_id (str): Wazuh agent ID.

        Returns:
            dict | None: Vulnerability payload, or None if no data is available
            or the request fails.
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
        self,
        agent_ids: Sequence[str],
        output_file: Optional[Path] = None,
    ) -> Union[Path, List[Path]]:
        """
        Retrieve vulnerabilities for a group of agents using OpenSearch
        (Wazuh API >= 4.8).

        Depending on `output_mode`, results are written either to a single JSON file
        or split into multiple chunk files (one per scroll page).

        Args:
            agent_ids (Sequence[str]): Wazuh agent IDs.
            output_file (Path | None): Base output file path. Defaults to 'wazuh.json'.

        Returns:
            Path: Path to the output JSON file (single mode).
            list[Path]: List of chunk file paths (split mode).
        """

        if output_file is None:
            output_file = Path("wazuh.json")
            self.logger.warning(
                "`output_file` is None. output_file will be set `wazuh.json`"
            )

        if self.opensearch_client is None:
            raise RuntimeError("OpenSearch client is not configured.")

        part_index = 1
        total_hits: Optional[int] = None
        seen_hits = 0
        scroll_id: Optional[str] = None
        output_files: List[Path] = []

        first_page = self._get_scroll_page(agent_ids=agent_ids)

        if not first_page:
            raise RuntimeError("First page is empty")

        scroll_id = first_page.get("_scroll_id", None)

        if not scroll_id:
            raise RuntimeError("OpenSearch response does not contain a scroll_id")

        hits_section = first_page.get("hits", None)
        if not hits_section:
            raise RuntimeError("OpenSearch response is missing the 'hits' section")
        hits = hits_section.get("hits", [])
        if not isinstance(hits, list):
            hits = []

        total_hits = (hits_section.get("total") or {}).get("value")
        seen_hits += len(hits)
        if isinstance(total_hits, int):
            if total_hits > len(hits):
                self.logger.info(f"Total hits - {total_hits}. Start scrolling...")
            else:
                self.logger.info(f"Total hits - {total_hits}")
        else:
            total_hits = None

        if self.output_mode == "split":
            chunk_file = self._chunk_output_path(output_file, part_index)
            self._write_json_file(chunk_file, first_page)
            part_index += 1
            output_files.append(chunk_file)

        if total_hits is not None and seen_hits >= total_hits:
            if scroll_id:
                self._clear_the_scroll_index(scroll_id)
            if self.output_mode == "single":
                self._write_json_file(output_file=output_file, payload=first_page)
                return output_file
            return output_files

        try:
            while True:
                page = self._get_scroll_page(scroll_id=scroll_id)

                if not isinstance(page, dict):
                    raise RuntimeError("Page is not a dict")

                scroll_id = page.get("_scroll_id", None)
                if not scroll_id:
                    raise RuntimeError("OpenSearch must have been return `scroll_id`")

                hits_section = page.get("hits", {})
                hits = hits_section.get("hits", [])
                if not isinstance(hits, list):
                    hits = []

                if len(hits) == 0:
                    self.logger.warning("No hits returned by OpenSearch scroll request")
                    break

                if self.output_mode == "single":
                    first_page["hits"]["hits"].extend(hits)
                else:
                    chunk_file = self._chunk_output_path(output_file, part_index)
                    self._write_json_file(chunk_file, page)
                    part_index += 1
                    output_files.append(chunk_file)

                seen_hits += len(hits)

                if total_hits is not None and seen_hits >= total_hits:
                    self.logger.warning(
                        f"Seen hits ({seen_hits}) exceed reported total hits ({total_hits}); stopping scroll"
                    )
                    break
        finally:
            if scroll_id:
                self._clear_the_scroll_index(scroll_id)
            else:
                self.logger.warning(
                    "`scroll_id` is None. Scroll index has not been cleared"
                )

        if self.output_mode == "single":
            self._write_json_file(output_file=output_file, payload=first_page)

        return output_files if self.output_mode == "split" else output_file

    def _get_scroll_page(
        self,
        agent_ids: Optional[Sequence[str]] = None,
        scroll_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Retrieve a page of results from OpenSearch using either an initial search
        or a scroll request.

        Exactly one of `agent_ids` or `scroll_id` must be provided.

        Args:
            agent_ids (Sequence[str] | None): Agent IDs for the initial search.
            scroll_id (str | None): Scroll ID for fetching the next page.

        Returns:
            dict: OpenSearch response payload.
        """
        try:
            if scroll_id:
                return self._opensearch_scroll_next(scroll_id)
            elif agent_ids:
                return self._opensearch_search_initial(agent_ids)
            else:
                raise RuntimeError("Either agent_ids or scroll_id must be provided")
        except AuthenticationException:
            raise RuntimeError("Received 401 Unauthorized.")
        except RequestError as re:
            raise RuntimeError(f"Received 400: {re}")
        except Exception as e:
            raise RuntimeError(
                f"Unexpected error while fetching group '{agent_ids}': {e}"
            )

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

        Notes:
            For Wazuh < 4.8, "split" writes chunks of 100000 hits. For 4.8+,
            "split" writes one file per scroll page.
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
            self._write_json_file(output_file, vulnerabilities_list)
            return output_file

        else:
            agent_ids: List[str] = []
            for agent in group_agents:
                agent_id = agent.get("id")
                if isinstance(agent_id, str):
                    agent_ids.append(agent_id)

            return self.get_vulnerabilities_for_group_of_agents_4_8_plus(
                agent_ids=agent_ids, output_file=output_file
            )
