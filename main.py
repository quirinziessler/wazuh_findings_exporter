"""Just a demo on how the wazuh.py file could be integrated"""

from wazuh_findings_exporter import Wazuh_Importer

Wazuh = Wazuh_Importer(BASE_URL=None, USERNAME=None, PASSWORD=None)

Wazuh.get_findings(group="Clients_AAAA", filedestination="")


# TODO: Update this example