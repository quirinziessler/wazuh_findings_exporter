from distutils.core import setup
setup(
  name = 'wazuh_findings_exporter',
  packages = ['wazuh_findings_exporter'],
  version = '1.0',
  license='MIT',
  description = 'Simple script that exports Wazuh Vulnerabilities by Agent groups',
  author = 'Quirin Hardy Zießler',
  author_email = 'quirin@ziessler.com',
  url = 'https://github.com/quirinziessler/wazuh_findings_exporter',
  download_url = 'https://github.com/quirinziessler/wazuh_findings_exporter',
  keywords = ['Wazuh', 'exporter', 'DefectDojo', 'Wazuh API'],
  install_requires=[
          'urllib3',
          'requests',
      ],
  classifiers=[
    '5 - Production/Stable',
    'Intended Audience :: Developers',
    'Topic :: Software Development :: Build Tools',
    'MIT License',
    'Programming Language :: Python :: 3',
    'Programming Language :: Python :: 3.6',
    'Programming Language :: Python :: 3.7',
    'Programming Language :: Python :: 3.8',
    'Programming Language :: Python :: 3.9',
    'Programming Language :: Python :: 3.11',
  ],
)