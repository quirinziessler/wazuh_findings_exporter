# wazuh_findings_exporter

A simple python script which exports findings of a client group from wazuh and adds the agent-ip as well as hostname to every finding for better further processing.

The script may not be perfect, so feel free to provide PRs and help to improve it.

## Usage

    from wazuh_findings_exporter import Wazuh_Importer

    Wazuh = Wazuh_Importer(BASE_URL=None, BASE_URL=None, BASE_URL=None)

    Wazuh.get_findings(group="Clients_AAAA", filedestination="")
