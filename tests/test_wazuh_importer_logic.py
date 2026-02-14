import json
import logging
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
from requests.exceptions import (
    ConnectTimeout,
    ConnectionError,
    ReadTimeout,
    RequestException,
)

from wazuh_findings_exporter.wazuh import Wazuh_Importer

BASE_URL = "https://test-wazuh-api"
USERNAME = "user"
PASSWORD = "pass"
OPENSEARCH_USERNAME = "os_user"
OPENSEARCH_PASSWORD = "os_pass"
OPENSEARCH_HOST = "os-host"


def _make_importer(api_version="4.7.0", **kwargs):
    def _set_version(self):
        self.wazuh_api_version = api_version
        return api_version

    with (
        patch.object(Wazuh_Importer, "authenticate", return_value=True),
        patch.object(Wazuh_Importer, "_get_api_version", autospec=True) as mock_get,
    ):
        mock_get.side_effect = _set_version
        return Wazuh_Importer(BASE_URL, USERNAME, PASSWORD, **kwargs)


def test_disable_insecure_request_warnings_calls_filters():
    importer = _make_importer(disable_insecure_request_warnings=False)
    with (
        patch("wazuh_findings_exporter.wazuh.warnings.filterwarnings") as mock_filter,
        patch("wazuh_findings_exporter.wazuh.urllib3.disable_warnings") as mock_disable,
    ):
        importer._disable_insecure_request_warnings()

    mock_filter.assert_called_once()
    mock_disable.assert_called_once()


def test_init_unknown_output_mode_falls_back_and_warns():
    logger = Mock(spec=logging.Logger)
    with (
        patch.object(Wazuh_Importer, "authenticate", return_value=True),
        patch.object(Wazuh_Importer, "_get_api_version", autospec=True) as mock_get,
        patch.object(
            Wazuh_Importer, "_disable_insecure_request_warnings"
        ) as mock_disable,
    ):
        mock_get.side_effect = lambda self: setattr(self, "wazuh_api_version", "4.7.0")
        importer = Wazuh_Importer(
            BASE_URL,
            USERNAME,
            PASSWORD,
            output_mode="weird",
            logger=logger,
            disable_insecure_request_warnings=False,
        )

    assert importer.output_mode == "single"
    logger.warning.assert_called_once()
    mock_disable.assert_not_called()


def test_init_creates_opensearch_client_for_4_8_plus():
    with (
        patch.object(Wazuh_Importer, "authenticate", return_value=True),
        patch.object(Wazuh_Importer, "_get_api_version", autospec=True) as mock_get,
        patch("wazuh_findings_exporter.wazuh.OpenSearch") as mock_opensearch,
    ):
        mock_get.side_effect = lambda self: setattr(self, "wazuh_api_version", "4.8.1")
        importer = Wazuh_Importer(
            BASE_URL,
            USERNAME,
            PASSWORD,
            OPENSEARCH_USERNAME=OPENSEARCH_USERNAME,
            OPENSEARCH_PASSWORD=OPENSEARCH_PASSWORD,
            OPENSEARCH_HOST=OPENSEARCH_HOST,
            OPENSEARCH_PORT=9201,
            verify=True,
        )

    mock_opensearch.assert_called_once_with(
        hosts=[{"host": OPENSEARCH_HOST, "port": 9201}],
        use_ssl=True,
        http_auth=(OPENSEARCH_USERNAME, OPENSEARCH_PASSWORD),
        verify_certs=True,
    )
    assert importer.opensearch_client == mock_opensearch.return_value


def test_init_does_not_create_opensearch_when_version_low():
    with (
        patch.object(Wazuh_Importer, "authenticate", return_value=True),
        patch.object(Wazuh_Importer, "_get_api_version", autospec=True) as mock_get,
        patch("wazuh_findings_exporter.wazuh.OpenSearch") as mock_opensearch,
    ):
        mock_get.side_effect = lambda self: setattr(self, "wazuh_api_version", "4.7.9")
        importer = Wazuh_Importer(
            BASE_URL,
            USERNAME,
            PASSWORD,
            OPENSEARCH_USERNAME=OPENSEARCH_USERNAME,
            OPENSEARCH_PASSWORD=OPENSEARCH_PASSWORD,
            OPENSEARCH_HOST=OPENSEARCH_HOST,
        )

    mock_opensearch.assert_not_called()
    assert importer.opensearch_client is None


def test_get_api_version_success_sets_value():
    with (
        patch.object(Wazuh_Importer, "authenticate", return_value=True),
        patch.object(Wazuh_Importer, "_get_api_version", return_value=None),
    ):
        importer = Wazuh_Importer(BASE_URL, USERNAME, PASSWORD)

    with patch("wazuh_findings_exporter.wazuh.requests.get") as mock_get:
        mock_get.return_value = Mock(
            status_code=200,
            json=Mock(
                return_value={"data": {"affected_items": [{"version": "4.7.0"}]}}
            ),
        )
        api_version = importer._get_api_version()

    assert api_version == "4.7.0"
    assert importer.wazuh_api_version == "4.7.0"


def test_get_api_version_reauth_on_401():
    with (
        patch.object(Wazuh_Importer, "authenticate", return_value=True),
        patch.object(Wazuh_Importer, "_get_api_version", return_value=None),
    ):
        importer = Wazuh_Importer(BASE_URL, USERNAME, PASSWORD)

    response_401 = Mock(status_code=401, text="unauthorized")
    response_200 = Mock(
        status_code=200,
        json=Mock(return_value={"data": {"affected_items": [{"version": "4.8.0"}]}}),
    )
    with (
        patch(
            "wazuh_findings_exporter.wazuh.requests.get",
            side_effect=[response_401, response_200],
        ) as mock_get,
        patch.object(importer, "authenticate", return_value=True) as mock_auth,
    ):
        api_version = importer._get_api_version()

    assert api_version == "4.8.0"
    mock_auth.assert_called_once()
    assert mock_get.call_count == 2


def test_get_api_version_non_200_returns_none():
    with (
        patch.object(Wazuh_Importer, "authenticate", return_value=True),
        patch.object(Wazuh_Importer, "_get_api_version", return_value=None),
    ):
        importer = Wazuh_Importer(BASE_URL, USERNAME, PASSWORD)

    with patch("wazuh_findings_exporter.wazuh.requests.get") as mock_get:
        mock_get.return_value = Mock(status_code=500, text="boom")
        api_version = importer._get_api_version()

    assert api_version is None


@pytest.mark.parametrize(
    "exc",
    [
        ConnectTimeout("t"),
        ReadTimeout("t"),
        ConnectionError("t"),
        RequestException("t"),
    ],
)
def test_get_api_version_request_exception_returns_none(exc):
    with (
        patch.object(Wazuh_Importer, "authenticate", return_value=True),
        patch.object(Wazuh_Importer, "_get_api_version", return_value=None),
    ):
        importer = Wazuh_Importer(BASE_URL, USERNAME, PASSWORD)

    with patch("wazuh_findings_exporter.wazuh.requests.get", side_effect=exc):
        api_version = importer._get_api_version()

    assert api_version is None


def test_authenticate_non_200_returns_false():
    with (
        patch("wazuh_findings_exporter.wazuh.requests.get") as mock_get,
        patch.object(Wazuh_Importer, "_get_api_version", return_value=None),
    ):
        mock_get.return_value = Mock(status_code=200, text="token")
        importer = Wazuh_Importer(BASE_URL, USERNAME, PASSWORD)

    with patch("wazuh_findings_exporter.wazuh.requests.get") as mock_get:
        mock_get.return_value = Mock(status_code=401, text="nope")
        assert importer.authenticate() is False


@pytest.mark.parametrize(
    "exc",
    [
        ConnectTimeout("t"),
        ReadTimeout("t"),
        ConnectionError("t"),
        RequestException("t"),
    ],
)
def test_authenticate_exception_returns_false(exc):
    with (
        patch("wazuh_findings_exporter.wazuh.requests.get") as mock_get,
        patch.object(Wazuh_Importer, "_get_api_version", return_value=None),
    ):
        mock_get.return_value = Mock(status_code=200, text="token")
        importer = Wazuh_Importer(BASE_URL, USERNAME, PASSWORD)

    with patch("wazuh_findings_exporter.wazuh.requests.get", side_effect=exc):
        assert importer.authenticate() is False


def test_get_agents_in_group_reauth_and_retry():
    importer = _make_importer()
    response_401 = Mock(status_code=401, text="unauthorized")
    response_200 = Mock(
        status_code=200,
        json=Mock(
            return_value={"data": {"affected_items": [{"id": "001", "os": "Ubuntu"}]}}
        ),
    )

    with (
        patch(
            "wazuh_findings_exporter.wazuh.requests.get",
            side_effect=[response_401, response_200],
        ) as mock_get,
        patch.object(importer, "authenticate", return_value=True) as mock_auth,
    ):
        agents = importer.get_agents_in_group("default")

    assert agents == [{"id": "001", "os": "Ubuntu"}]
    mock_auth.assert_called_once()
    assert mock_get.call_count == 2


def test_get_agents_in_group_non_200_returns_empty():
    importer = _make_importer()
    with patch("wazuh_findings_exporter.wazuh.requests.get") as mock_get:
        mock_get.return_value = Mock(status_code=500, text="oops")
        agents = importer.get_agents_in_group("default")

    assert agents == []


@pytest.mark.parametrize(
    "exc",
    [
        ConnectTimeout("t"),
        ReadTimeout("t"),
        ConnectionError("t"),
        RequestException("t"),
    ],
)
def test_get_agents_in_group_exception_returns_empty(exc):
    importer = _make_importer()
    with patch("wazuh_findings_exporter.wazuh.requests.get", side_effect=exc):
        agents = importer.get_agents_in_group("default")

    assert agents == []


def test_get_vulnerabilities_for_agent_reauth_and_retry():
    importer = _make_importer()
    response_401 = Mock(status_code=401, text="unauthorized")
    response_200 = Mock(
        status_code=200,
        json=Mock(return_value={"data": {"affected_items": [{"id": "CVE-1"}]}}),
    )

    with (
        patch(
            "wazuh_findings_exporter.wazuh.requests.get",
            side_effect=[response_401, response_200],
        ) as mock_get,
        patch.object(importer, "authenticate", return_value=True) as mock_auth,
    ):
        vulns = importer.get_vulnerabilities_for_agent("001")

    assert vulns["data"]["affected_items"][0]["id"] == "CVE-1"
    mock_auth.assert_called_once()
    assert mock_get.call_count == 2


@pytest.mark.parametrize("status_code", [400, 404, 500])
def test_get_vulnerabilities_for_agent_non_200_returns_none(status_code):
    importer = _make_importer()
    with patch("wazuh_findings_exporter.wazuh.requests.get") as mock_get:
        mock_get.return_value = Mock(status_code=status_code, text="oops")
        assert importer.get_vulnerabilities_for_agent("001") is None


@pytest.mark.parametrize(
    "exc",
    [
        ConnectTimeout("t"),
        ReadTimeout("t"),
        ConnectionError("t"),
        RequestException("t"),
    ],
)
def test_get_vulnerabilities_for_agent_exception_returns_none(exc):
    importer = _make_importer()
    with patch("wazuh_findings_exporter.wazuh.requests.get", side_effect=exc):
        assert importer.get_vulnerabilities_for_agent("001") is None


def test_get_scroll_page_routes_initial_and_scroll():
    importer = _make_importer(api_version="4.8.0")
    with (
        patch.object(
            importer, "_opensearch_search_initial", return_value={"ok": True}
        ) as mock_initial,
        patch.object(
            importer, "_opensearch_scroll_next", return_value={"scroll": True}
        ) as mock_scroll,
    ):
        initial = importer._get_scroll_page(agent_ids=["001"])
        scroll = importer._get_scroll_page(scroll_id="abc")

    assert initial == {"ok": True}
    assert scroll == {"scroll": True}
    mock_initial.assert_called_once_with(["001"])
    mock_scroll.assert_called_once_with("abc")


def test_get_scroll_page_requires_params():
    importer = _make_importer(api_version="4.8.0")
    with pytest.raises(RuntimeError):
        importer._get_scroll_page()


def test_get_vulnerabilities_for_group_of_agents_4_8_plus_without_client_raises():
    importer = _make_importer(api_version="4.8.0")
    importer.opensearch_client = None
    with pytest.raises(RuntimeError):
        importer.get_vulnerabilities_for_group_of_agents_4_8_plus(agent_ids=["001"])


def test_get_vulnerabilities_for_group_of_agents_4_8_plus_single_merges_hits(tmp_path):
    importer = _make_importer(api_version="4.8.0")
    importer.opensearch_client = Mock()
    importer.output_mode = "single"
    output_file = tmp_path / "wazuh.json"

    first_page = {
        "_scroll_id": "s1",
        "hits": {"total": {"value": 3}, "hits": [{"_id": "1"}]},
    }
    next_page = {"_scroll_id": "s2", "hits": {"hits": [{"_id": "2"}, {"_id": "3"}]}}

    with patch.object(
        importer, "_get_scroll_page", side_effect=[first_page, next_page]
    ):
        result = importer.get_vulnerabilities_for_group_of_agents_4_8_plus(
            agent_ids=["001"],
            output_file=output_file,
        )

    assert result == output_file
    with open(output_file, encoding="utf-8") as f:
        payload = json.load(f)
    assert [hit["_id"] for hit in payload["hits"]["hits"]] == ["1", "2", "3"]
    importer.opensearch_client.clear_scroll.assert_called_once_with(scroll_id="s2")


def test_get_vulnerabilities_for_group_of_agents_4_8_plus_split_writes_chunks(tmp_path):
    importer = _make_importer(api_version="4.8.0")
    importer.opensearch_client = Mock()
    importer.output_mode = "split"
    output_file = tmp_path / "wazuh.json"

    pages = [
        {
            "_scroll_id": "s1",
            "hits": {"total": {"value": 3}, "hits": [{"_id": "1"}]},
        },
        {"_scroll_id": "s2", "hits": {"hits": [{"_id": "2"}]}},
        {"_scroll_id": "s3", "hits": {"hits": []}},
    ]

    with patch.object(importer, "_get_scroll_page", side_effect=pages):
        files = importer.get_vulnerabilities_for_group_of_agents_4_8_plus(
            agent_ids=["001"],
            output_file=output_file,
        )

    assert [p.name for p in files] == ["wazuh_0001.json", "wazuh_0002.json"]
    with open(files[0], encoding="utf-8") as f:
        assert json.load(f) == pages[0]
    with open(files[1], encoding="utf-8") as f:
        assert json.load(f) == pages[1]

    importer.opensearch_client.clear_scroll.assert_called_once_with(scroll_id="s3")


def test_chunked_and_chunk_output_path():
    importer = _make_importer()
    chunks = list(importer._chunked([1, 2, 3, 4, 5], 2))
    assert chunks == [[1, 2], [3, 4], [5]]

    output = importer._chunk_output_path(Path("/tmp/wazuh.json"), 3)
    assert output.name == "wazuh_0003.json"


def test_write_json_file_writes_and_handles_errors(tmp_path):
    importer = _make_importer()
    output_file = tmp_path / "out.json"
    importer._write_json_file(output_file, {"a": 1})

    with open(output_file, encoding="utf-8") as f:
        assert json.load(f) == {"a": 1}

    importer.logger = Mock(spec=logging.Logger)
    with patch("wazuh_findings_exporter.wazuh.open", side_effect=OSError("boom")):
        importer._write_json_file(output_file, {"b": 2})

    importer.logger.error.assert_called_once()


def test_get_findings_pre_4_8_filters_and_enriches(tmp_path):
    importer = _make_importer(api_version="4.7.0")
    group_agents = [
        {"id": "001", "ip": "1.1.1.1", "name": "host1"},
        {"id": "002", "ip": "1.1.1.2", "name": "host2"},
    ]

    def mock_vulns(agent_id):
        if agent_id == "001":
            return {
                "data": {
                    "affected_items": [
                        {"id": "CVE-1", "condition": "Package fixed"},
                        {"id": "CVE-2", "condition": "Package unfixed"},
                    ]
                }
            }
        return None

    with (
        patch.object(importer, "get_agents_in_group", return_value=group_agents),
        patch.object(importer, "get_vulnerabilities_for_agent", side_effect=mock_vulns),
    ):
        output_file = importer.get_findings("default", tmp_path)

    with open(output_file, encoding="utf-8") as f:
        payload = json.load(f)

    assert payload["data"]["total_affected_items"] == 1
    assert payload["data"]["affected_items"][0]["id"] == "CVE-1"
    assert payload["data"]["affected_items"][0]["agent_ip"] == "1.1.1.1"
    assert payload["data"]["affected_items"][0]["agent_name"] == "host1"


def test_get_findings_4_8_plus_filters_agent_ids_and_delegates(tmp_path):
    importer = _make_importer(api_version="4.8.0")
    sentinel = tmp_path / "wazuh.json"
    agents = [{"id": "001"}, {"id": 2}]

    with (
        patch.object(importer, "get_agents_in_group", return_value=agents),
        patch.object(
            importer,
            "get_vulnerabilities_for_group_of_agents_4_8_plus",
            return_value=sentinel,
        ) as mock_writer,
    ):
        result = importer.get_findings("default", tmp_path)

    assert result == sentinel
    mock_writer.assert_called_once_with(
        agent_ids=["001"],
        output_file=Path(tmp_path) / "wazuh.json",
    )
