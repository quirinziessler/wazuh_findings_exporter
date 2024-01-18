''' Just a demo on how the wazuh.py file could be integrated '''

import wazuh_findings_exporter import Wazuh_Importer

Wazuh = Wazuh_Importer(BASE_URL=None, BASE_URL=None, BASE_URL=None)

Wazuh.get_findings(group="Clients_AAAA", filedestination="")