from __future__ import print_function
import splunklib.client as client
import splunklib.results as results

HOST = "localhost"
PORT = 8089
USERNAME = "hkumba"
PASSWORD = "Siem@123"


# Create a Service instance and log in 
service = client.connect(
    host=HOST,
    port=PORT,
    username=USERNAME,
    password=PASSWORD)

# Print installed apps to the console to verify login
for app in service.jobs:
    print (app.name)

# rr = results.ResultsReader(service.jobs.export("search index=_internal earliest=-1h | head 5"))
# for result in rr:
#     if isinstance(result, results.Message):
#         # Diagnostic messages might be returned in the results
#         print('%s: %s' % (result.type, result.message))
#     elif isinstance(result, dict):
#         # Normal events are returned as dicts
#         print(result)

# assert rr.is_preview == False