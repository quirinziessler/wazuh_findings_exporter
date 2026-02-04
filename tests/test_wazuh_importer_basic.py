from pathlib import Path
from unittest.mock import Mock, patch
import json
import pytest

from wazuh_findings_exporter.wazuh import Wazuh_Importer

BASE_URL = "https://test-wazuh-api"
USERNAME = "user"
PASSWORD = "pass"
OPENSEARCH_USERNAME = "os_user"
OPENSEARCH_PASSWORD = "os_pass"
OPENSEARCH_HOST = "os-host"


def _mock_auth_and_version(api_version: str):
    def mock_get(url, *args, **kwargs):
        mock_resp = Mock()
        if url.endswith("/security/user/authenticate?raw=true"):
            mock_resp.status_code = 200
            mock_resp.text = "fake_token"
        elif url.endswith("/manager/info"):
            mock_resp.status_code = 200
            mock_resp.json.return_value = {
                "data": {"affected_items": [{"version": api_version}]}
            }
        else:
            mock_resp.status_code = 404
            mock_resp.text = "not found"
        return mock_resp

    return mock_get


def test_importer_authenticate_sets_token():
    """Check that HEADERS contains Authorization after authenticate."""
    with patch(
        "wazuh_findings_exporter.wazuh.requests.get",
        side_effect=_mock_auth_and_version("4.7.0"),
    ):
        importer = Wazuh_Importer(BASE_URL, USERNAME, PASSWORD)
        assert importer.HEADERS["Authorization"] == "Bearer fake_token"


def test_get_agents_in_group_returns_list():
    """Check that get_agents_in_group returns the affected_items list."""

    def mock_get(url, *args, **kwargs):
        mock_resp = Mock()
        if url.endswith("/security/user/authenticate?raw=true"):
            mock_resp.status_code = 200
            mock_resp.text = "fake_token"
        elif url.endswith("/manager/info"):
            mock_resp.status_code = 200
            mock_resp.json.return_value = {
                "data": {"affected_items": [{"version": "4.7.0"}]}
            }
        elif url.endswith("/groups/default/agents"):
            mock_resp.status_code = 200
            mock_resp.json.return_value = {
                "data": {
                    "affected_items": [
                        {"os": "Ubuntu", "id": "001", "ip": "1.2.3.4", "name": "host1"}
                    ]
                }
            }
        else:
            mock_resp.status_code = 404
            mock_resp.text = "not found"
        return mock_resp

    with patch("wazuh_findings_exporter.wazuh.requests.get", side_effect=mock_get):
        importer = Wazuh_Importer(BASE_URL, USERNAME, PASSWORD)
        agents = importer.get_agents_in_group("default")

    assert isinstance(agents, list)
    assert agents[0]["os"] == "Ubuntu"
    assert agents[0]["id"] == "001"


def test_get_vulnerabilities_for_agent_returns_data():
    """Check that vulnerabilities are returned correctly (Wazuh API < 4.8)."""

    def mock_get(url, *args, **kwargs):
        mock_resp = Mock()
        if url.endswith("/security/user/authenticate?raw=true"):
            mock_resp.status_code = 200
            mock_resp.text = "fake_token"
        elif url.endswith("/manager/info"):
            mock_resp.status_code = 200
            mock_resp.json.return_value = {
                "data": {"affected_items": [{"version": "4.7.0"}]}
            }
        elif url.endswith("/vulnerability/001"):
            mock_resp.status_code = 200
            mock_resp.json.return_value = {
                "data": {
                    "affected_items": [{"id": "CVE-1234", "condition": "Package fixed"}]
                }
            }
        else:
            mock_resp.status_code = 404
            mock_resp.text = "not found"
        return mock_resp

    with patch("wazuh_findings_exporter.wazuh.requests.get", side_effect=mock_get):
        importer = Wazuh_Importer(BASE_URL, USERNAME, PASSWORD)
        vulns = importer.get_vulnerabilities_for_agent("001")

    assert isinstance(vulns, dict)
    assert vulns["data"]["affected_items"][0]["id"] == "CVE-1234"


def test_get_vulnerabilities_for_group_of_agents_4_8_plus_writes_file(tmp_path):
    """Check that OpenSearch results are written to disk for 4.8+."""
    first_page = {
        "_scroll_id": "s1",
        "hits": {"total": {"value": 2}, "hits": [{"_id": "1"}, {"_id": "2"}]},
    }

    with (
        patch(
            "wazuh_findings_exporter.wazuh.requests.get",
            side_effect=_mock_auth_and_version("4.8.0"),
        ),
        patch("wazuh_findings_exporter.wazuh.OpenSearch") as mock_opensearch,
    ):
        mock_client = Mock()
        mock_client.search.return_value = first_page
        mock_opensearch.return_value = mock_client

        importer = Wazuh_Importer(
            BASE_URL,
            USERNAME,
            PASSWORD,
            OPENSEARCH_USERNAME=OPENSEARCH_USERNAME,
            OPENSEARCH_PASSWORD=OPENSEARCH_PASSWORD,
            OPENSEARCH_HOST=OPENSEARCH_HOST,
        )
        output_file = tmp_path / "wazuh.json"
        result = importer.get_vulnerabilities_for_group_of_agents_4_8_plus(
            agent_ids=["001", "002"],
            output_file=output_file,
        )

    assert result == output_file
    assert output_file.exists()
    with open(output_file, encoding="utf-8") as f:
        assert json.load(f) == first_page

    mock_client.clear_scroll.assert_called_once_with(scroll_id="s1")
    search_kwargs = mock_client.search.call_args.kwargs
    assert search_kwargs["index"] == importer.elasticsearch_index
    assert search_kwargs["body"]["query"]["bool"]["must"][0]["terms"]["agent.id"] == [
        "001",
        "002",
    ]


def test_get_vulnerabilities_for_group_of_agents_4_8_plus_without_client():
    """Check that missing OpenSearch client raises an error."""
    with patch(
        "wazuh_findings_exporter.wazuh.requests.get",
        side_effect=_mock_auth_and_version("4.8.0"),
    ):
        importer = Wazuh_Importer(BASE_URL, USERNAME, PASSWORD)

    with pytest.raises(RuntimeError):
        importer.get_vulnerabilities_for_group_of_agents_4_8_plus(agent_ids=["001"])


def test_get_findings_creates_json_file(tmp_path):
    """Check that get_findings writes a valid JSON file."""

    def mock_get(url, *args, **kwargs):
        mock_resp = Mock()
        if url.endswith("/security/user/authenticate?raw=true"):
            mock_resp.status_code = 200
            mock_resp.text = "fake_token"
        elif url.endswith("/manager/info"):
            mock_resp.status_code = 200
            mock_resp.json.return_value = {
                "data": {"affected_items": [{"version": "4.7.0"}]}
            }
        else:
            mock_resp.status_code = 404
        return mock_resp

    with (
        patch("wazuh_findings_exporter.wazuh.requests.get", side_effect=mock_get),
        patch(
            "wazuh_findings_exporter.wazuh.Wazuh_Importer.get_agents_in_group"
        ) as mock_agents,
        patch(
            "wazuh_findings_exporter.wazuh.Wazuh_Importer.get_vulnerabilities_for_agent"
        ) as mock_vulns,
    ):
        mock_agents.return_value = [{"id": "001", "ip": "1.2.3.4", "name": "host1"}]
        mock_vulns.return_value = {
            "data": {
                "affected_items": [{"id": "CVE-1234", "condition": "Package fixed"}]
            }
        }

        importer = Wazuh_Importer(BASE_URL, USERNAME, PASSWORD)
        output_file = importer.get_findings("default", tmp_path)

    assert output_file.exists()
    with open(output_file, encoding="utf-8") as f:
        data = json.load(f)
        assert data["data"]["total_affected_items"] == 1
        assert data["data"]["affected_items"][0]["id"] == "CVE-1234"


def test_get_findings_uses_opensearch_for_4_8_plus(tmp_path):
    """Check that get_findings delegates to OpenSearch for Wazuh API >= 4.8."""
    sentinel = tmp_path / "wazuh.json"

    with (
        patch.object(Wazuh_Importer, "authenticate", return_value=True),
        patch.object(Wazuh_Importer, "_get_api_version", autospec=True) as mock_get,
    ):
        mock_get.side_effect = lambda self: setattr(self, "wazuh_api_version", "4.8.0")
        importer = Wazuh_Importer(BASE_URL, USERNAME, PASSWORD)

    with (
        patch.object(importer, "get_agents_in_group") as mock_agents,
        patch.object(
            importer, "get_vulnerabilities_for_group_of_agents_4_8_plus"
        ) as mock_vulns,
    ):
        mock_agents.return_value = [
            {"id": "001", "ip": "1.2.3.4", "name": "host1"},
            {"id": "002", "ip": "1.2.3.5", "name": "host2"},
        ]
        mock_vulns.return_value = sentinel

        output_file = importer.get_findings("default", tmp_path)

    assert output_file == sentinel
    mock_vulns.assert_called_once_with(
        agent_ids=["001", "002"], output_file=Path(tmp_path) / "wazuh.json"
    )
