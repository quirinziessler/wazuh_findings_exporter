from unittest.mock import patch, Mock
from wazuh_findings_exporter.wazuh import Wazuh_Importer
import json

BASE_URL = "https://test-wazuh-api"
USERNAME = "user"
PASSWORD = "pass"


def test_importer_authenticate_sets_token():
    """Check that HEADERS contains Authorization after authenticate"""
    with patch("wazuh_findings_exporter.wazuh.requests.get") as mock_get:
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "test_token"
        mock_get.return_value = mock_response

        importer = Wazuh_Importer(BASE_URL, USERNAME, PASSWORD)
        assert importer.HEADERS["Authorization"] == "Bearer test_token"


def test_get_agents_in_group_returns_list():
    """Check that get_agents_in_group returns the affected_items list"""
    with patch("wazuh_findings_exporter.wazuh.requests.get") as mock_get:
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": {
                "affected_items": [
                    {"os": "Ubuntu", "id": "001", "ip": "1.2.3.4", "name": "host1"}
                ]
            }
        }

        mock_get.return_value = mock_response

        importer = Wazuh_Importer(BASE_URL, USERNAME, PASSWORD)
        agents = importer.get_agents_in_group("default")
        assert isinstance(agents, list)
        assert agents[0]["os"] == "Ubuntu"
        assert agents[0]["id"] == "001"


def test_get_vulnerabilities_for_agent_returns_data():
    """Check that vulnerabilities are returned correctly (Wazuh API < 4.8)."""
    with patch("wazuh_findings_exporter.wazuh.requests.get") as mock_get:
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": {
                "affected_items": [{"id": "CVE-1234", "condition": "Package fixed"}]
            }
        }
        mock_get.return_value = mock_response

        importer = Wazuh_Importer(BASE_URL, USERNAME, PASSWORD)
        vulns = importer.get_vulnerabilities_for_agent("001")
        assert isinstance(vulns, dict)
        assert vulns["data"]["affected_items"][0]["id"] == "CVE-1234"


def test_get_vulnerabilities_for_group_of_agents_4_8_plus():
    """Check that vulnerabilities are returned correctly (Wazuh API >= 4.8)."""
    pass  # TODO: implement test with mock for get_vulnerabilities_for_group_of_agents_4_8_plus


def test_get_findings_creates_json_file(tmp_path):
    """Check that get_findings writes a valid JSON file"""
    
    # side_effect для разных URL
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

    with patch("wazuh_findings_exporter.wazuh.requests.get", side_effect=mock_get), \
         patch("wazuh_findings_exporter.wazuh.Wazuh_Importer.get_agents_in_group") as mock_agents, \
         patch("wazuh_findings_exporter.wazuh.Wazuh_Importer.get_vulnerabilities_for_agent") as mock_vulns:
   
        mock_agents.return_value = [{"id": "001", "ip": "1.2.3.4", "name": "host1"}]
        mock_vulns.return_value = {
            "data": {"affected_items": [{"id": "CVE-1234", "condition": "Package fixed"}]}
        }

        importer = Wazuh_Importer(BASE_URL, USERNAME, PASSWORD)
        output_file = importer.get_findings("default", tmp_path)

        # Проверка файла
        assert output_file.exists()
        with open(output_file) as f:
            data = json.load(f)
            assert data["data"]["total_affected_items"] == 1
            assert data["data"]["affected_items"][0]["id"] == "CVE-1234"
