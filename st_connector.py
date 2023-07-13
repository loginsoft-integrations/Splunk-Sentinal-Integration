import json
import requests
import datetime
import hashlib
import hmac
import base64

# Update the customer ID to your Log Analytics workspace ID
customer_id = '97e2db05-0037-49e5-a6d0-8ce0ce4c4e3d'

# For the shared key, use either the primary or the secondary Connected Sources client authentication key   
shared_key = "ioht9zXC2Bbw9NqCP3c5cq4Zk8qmnQ5V25wDbmiXOLtKzbeEhn5jT76TeA8rcMDI6AZdzujCnBu1KP0uSzc4nw=="

# The log type is the name of the event that is being submitted
log_type = 'WindowsEventTest'

# An example JSON web monitor object
json_data = [{"preview":"false","offset":"0","result":{"_bkt":"_internal~0~1B2E9F93-3AED-4A89-A71C-EA802881F905","_cd":"0:2430736","_indextime":"1689074118","_raw":"07-11-2023 16:45:18.002 +0530 INFO  Metrics - group=dutycycle, name=misc, mgmt_httpd=0.001, reaper=0.000, saved_search_fetcher=0.001, savedsplunker=0.000, tail=0.088, udpin=0.000","_serial":"0","_si":["Haris-MacBook-Pro.local","_internal"],"_sourcetype":"splunkd","_subsecond":".002","_time":"1689074118.002","host":"Haris-MacBook-Pro.local","index":"_internal","linecount":"1","source":"/Applications/Splunk/var/log/splunk/metrics.log","sourcetype":"splunkd","splunk_server":"Haris-MacBook-Pro.local"}}]
body = json.dumps(json_data)

#####################
######Functions######  
#####################

# Build the API signature
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
    rfc1123date = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
    content_length = len(body)
    signature = build_signature(customer_id, shared_key, rfc1123date, content_length, method, content_type, resource)
    uri = 'https://' + customer_id + '.ods.opinsights.azure.com' + resource + '?api-version=2016-04-01'

    headers = {
        'content-type': content_type,
        'Authorization': signature,
        'Log-Type': log_type,
        'x-ms-date': rfc1123date
    }

    response = requests.post(uri,data=body, headers=headers)
    if (response.status_code >= 200 and response.status_code <= 299):
        print('Accepted')
    else:
        print("Response code: {}".format(response.status_code))

post_data(customer_id, shared_key, body, log_type)