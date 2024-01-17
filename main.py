''' Just a demo on how the wazuh.py file could be integrated '''

from wazuh import Wazuh_Importer

Wazuh = Wazuh_Importer()

Wazuh.get_findings(group="Clients_AAAA", filedestination="")