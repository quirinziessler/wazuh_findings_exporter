"""Demo for using the wazuh_findings_exporter module."""

from wazuh_findings_exporter import Wazuh_Importer

WAZUH_URL = "https://wazuh.example.local"
WAZUH_USER = "wazuh-user"
WAZUH_PASS = "wazuh-pass"

# Optional for Wazuh 4.8+ (OpenSearch access)
OS_USER = "opensearch-user"
OS_PASS = "opensearch-pass"
OS_HOST = "opensearch.example.local"
OS_PORT = 9200

EXPORT_DIR = "output"

importer = Wazuh_Importer(
    BASE_URL=WAZUH_URL,
    USERNAME=WAZUH_USER,
    PASSWORD=WAZUH_PASS,
    OPENSEARCH_USERNAME=OS_USER,
    OPENSEARCH_PASSWORD=OS_PASS,
    OPENSEARCH_HOST=OS_HOST,
    OPENSEARCH_PORT=OS_PORT,
    output_mode="split",
    verify=False,
    timeout=30,
)

result = importer.get_findings(
    group="Clients_AAAA",
    filedestination=EXPORT_DIR,
    filename="wazuh.json",
)

print(f"Saved results: {result}")
