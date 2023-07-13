import base64
import hashlib
import hmac
from base64 import b64encode, b64decode
from hashlib import sha256
from hmac import new as new_hash
from datetime import datetime
from json import dump, dumps
from typing import Any

from splunklib.results import JSONResultsReader, Message
from splunklib.client import Service
from splunklib import client
from requests import post

from config import SPLUNK_HOST, SPLUNK_PORT, SPLUNK_USER, SPLUNK_PASSWORD
from config import SENTINEL_CUSTOMER_ID, SENTINEL_LOG_TYPE, SENTINEL_SHARED_KEY


# Step 1 : Create connection to Splunk
def connect_to_splunk(host, port, user, password) -> Service:
    try:
        connection = client.connect(host=host, port=port, username=user, password=password)
        return connection
    except ConnectionError as ex:
        print(ex)
        # TODO log error
        ...


# Step 2 : Build Query/Search string
# Step 3: Export JSON
def export_to_json(connection: Service, source_type: str, time_range: str = "last_hour"):
    search_query = 'search index="microsoft_sentinel_migration" sourcetype="{0}" earliest=-1y@y latest=+1y@y'.format(source_type)
    export_job = connection.jobs.export(search_query, output_mode='json')

    # Use the JSONResultsReader class to read the results as JSON objects.
    json_result = JSONResultsReader(export_job)
    # for result in json_result:
    #     if isinstance(result, Message):
    #         # Diagnostic messages might be returned in the results
    #         print('%s: %s' % (result.type, result.message))
    #     elif isinstance(result, dict):
    #         # Normal events are returned as dicts
    #         print(result)
    # Remove invalid records
    return list(filter(lambda x: isinstance(x, dict), json_result))


def save_json_to_file(file_name: str, data: list[Any]):
    with open(file_name, 'w') as f:
        dump(data, f)


# # Step 4 : Send Data to Sentinel
# # Build the API signature
# def build_signature(customer_id, shared_key, date, content_length, method, content_type, resource):
#     x_headers = 'x-ms-date:' + date
#     string_to_hash = method + "\n" + str(content_length) + "\n" + content_type + "\n" + x_headers + "\n" + resource
#     bytes_to_hash = bytes(string_to_hash, encoding="utf-8")
#     decoded_key = base64.b64decode(shared_key)
#     encoded_hash = base64.b64encode(hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()).decode()
#     authorization = "SharedKey {}:{}".format(customer_id, encoded_hash)
#     return authorization
#
#
# # https://winevtlogmonitor-ubbf.eastus-1.ingest.monitor.azure.com
# # Build and send a request to the POST API
# def send_data_to_sentinel(customer_id, shared_key, log_type, body):
#     method = 'POST'
#     content_type = 'application/json'
#     resource = '/api/logs'
#     rfc1123date = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
#     content_length = len(body)
#     signature = build_signature(customer_id, shared_key, rfc1123date, content_length, method, content_type, resource)
#     uri = 'https://' + customer_id + '.ods.opinsights.azure.com' + resource + '?api-version=2016-04-01'
#
#     headers = {
#         'content-type': content_type,
#         'Authorization': signature,
#         'Log-Type': log_type,
#         'x-ms-date': rfc1123date
#     }
#
#     response = post(uri, data=dumps(body), headers=headers)
#     if (response.status_code >= 200 and response.status_code <= 299):
#         print('Accepted')
#     else:
#         print("Response code: {}".format(response.status_code))

def build_signature(customer_id, shared_key, date, content_length, method, content_type, resource):
    x_headers = 'x-ms-date:' + date
    string_to_hash = method + "\n" + str(content_length) + "\n" + content_type + "\n" + x_headers + "\n" + resource
    bytes_to_hash = bytes(string_to_hash, encoding="utf-8")
    decoded_key = base64.b64decode(shared_key)
    encoded_hash = base64.b64encode(hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()).decode()
    authorization = "SharedKey {}:{}".format(customer_id,encoded_hash)
    return authorization
#https://winevtlogmonitor-ubbf.eastus-1.ingest.monitor.azure.com
# Build and send a request to the POST API
def post_data(customer_id, shared_key, body, log_type):
    method = 'POST'
    content_type = 'application/json'
    resource = '/api/logs'
    rfc1123date = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
    content_length = len(body)
    signature = build_signature(customer_id, shared_key, rfc1123date, content_length, method, content_type, resource)
    uri = 'https://' + customer_id + '.ods.opinsights.azure.com' + resource + '?api-version=2016-04-01'

    headers = {
        'content-type': content_type,
        'Authorization': signature,
        'Log-Type': log_type,
        'x-ms-date': rfc1123date
    }

    response = post(uri,data=body, headers=headers)
    if (response.status_code >= 200 and response.status_code <= 299):
        print('Accepted')
    else:
        print("Response code: {}".format(response.status_code))

if __name__ == '__main__':
    import pdb
    pdb.set_trace()
    # connection = connect_to_splunk(SPLUNK_HOST, SPLUNK_PORT, SPLUNK_USER, SPLUNK_PASSWORD)
    # json_data = export_to_json(connection, "csv") # TODO read source_type from user
    json_data = [{"preview": "false", "offset": "0",
                  "result": {"_bkt": "_internal~0~1B2E9F93-3AED-4A89-A71C-EA802881F905", "_cd": "0:2430736",
                             "_indextime": "1689074118",
                             "_raw": "07-11-2023 16:45:18.002 +0530 INFO  Metrics - group=dutycycle, name=misc, mgmt_httpd=0.001, reaper=0.000, saved_search_fetcher=0.001, savedsplunker=0.000, tail=0.088, udpin=0.000",
                             "_serial": "0", "_si": ["Haris-MacBook-Pro.local", "_internal"], "_sourcetype": "splunkd",
                             "_subsecond": ".002", "_time": "1689074118.002", "host": "Haris-MacBook-Pro.local",
                             "index": "_internal", "linecount": "1",
                             "source": "/Applications/Splunk/var/log/splunk/metrics.log", "sourcetype": "splunkd",
                             "splunk_server": "Haris-MacBook-Pro.local"}}]
    print(f"{SENTINEL_CUSTOMER_ID=}, {SENTINEL_SHARED_KEY=}, {SENTINEL_LOG_TYPE=}")
    body = dumps(json_data)
    post_data(SENTINEL_CUSTOMER_ID, SENTINEL_SHARED_KEY, body, SENTINEL_LOG_TYPE)