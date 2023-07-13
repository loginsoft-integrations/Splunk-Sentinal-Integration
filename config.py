from tomllib import load
from pathlib import Path

CONFIG = {}
with open(Path("config.toml"), 'rb') as config_file:
    CONFIG = load(config_file)

SPLUNK_HOST = CONFIG.get('splunk', {}).get('host')
SPLUNK_PORT = CONFIG.get('splunk', {}).get('port')
SPLUNK_USER = CONFIG.get('splunk', {}).get('user')
SPLUNK_PASSWORD = CONFIG.get('splunk', {}).get('password')

SENTINEL_CUSTOMER_ID = CONFIG.get('microsoft_sentinel', {}).get('customer_id')
SENTINEL_SHARED_KEY = CONFIG.get('microsoft_sentinel', {}).get('shared_key')
SENTINEL_LOG_TYPE = CONFIG.get('microsoft_sentinel', {}).get('log_type')
