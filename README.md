# wazuh_findings_exporter

A simple python script which exports findings of a client group from wazuh and adds the agent-ip as well as hostname to every finding for better further processing.

The script may not be perfect, so feel free to provide PRs and help to improve it.
 
For Wazuh versions below 4.8 it enriches each finding with `agent_ip` and `agent_name`.  
For Wazuh 4.8+ it queries OpenSearch directly.

## Usage

```python
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
```

## Parameters

`Wazuh_Importer(...)` parameters:

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `BASE_URL` | `str` | required | Base URL of the Wazuh API, e.g. `https://wazuh.example.local:55000`. |
| `USERNAME` | `str` | required | Wazuh API username. |
| `PASSWORD` | `str` | required | Wazuh API password. |
| `OPENSEARCH_USERNAME` | `str` | `""` | OpenSearch username (used for Wazuh 4.8+). |
| `OPENSEARCH_PASSWORD` | `str` | `""` | OpenSearch password (used for Wazuh 4.8+). |
| `OPENSEARCH_HOST` | `str` | `""` | OpenSearch host (Wazuh 4.8+). |
| `OPENSEARCH_PORT` | `int` | `9200` | OpenSearch port (Wazuh 4.8+). |
| `verify` | `bool` | `False` | Verify TLS certificates for API/OpenSearch calls. |
| `timeout` | `float` | `10` | Request timeout in seconds. |
| `elasticsearch_index` | `str` | `wazuh-states-vulnerabilities-*` | OpenSearch index pattern for vulnerabilities. |
| `output_mode` | `str` | `single` | `single` writes one file; `split` writes chunks of 100000 hits per file. |
| `logger` | `logging.Logger` | `None` | Custom logger instance. |
| `disable_insecure_request_warnings` | `bool` | `True` | Suppress insecure HTTPS warnings when `verify=False`. |

`get_findings(...)` parameters:

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `group` | `str` | required | Wazuh group name. |
| `filedestination` | `str` | required | Directory where the JSON output will be saved. Created if missing. |
| `filename` | `str` | `wazuh.json` | Output filename. |

## How It Works

- The importer authenticates to the Wazuh API and fetches the API version.
- Wazuh < 4.8 behavior: script calls `/vulnerability/{agent_id}` per agent, filters out findings with `condition == "Package unfixed"`, and adds `agent_ip` and `agent_name` to each finding.
- Wazuh >= 4.8 behavior: script queries OpenSearch using the configured credentials and streams results using OpenSearch scrolls.

## Output

- `output_mode="single"` returns a single `Path` to the JSON file.
- `output_mode="split"` returns a list of `Path` objects, one per chunk.
