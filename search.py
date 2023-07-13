# sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
import sys
from time import sleep
import splunklib.results as results

HOST = "localhost"
PORT = 8089
USERNAME = "hkumba"
PASSWORD = "Siem@123"

# ...
# 
# Initialize your service like so
import splunklib.client as client
service = client.connect(
    host=HOST,
    port=PORT,
    username=USERNAME,
    password=PASSWORD)

searchquery_normal = 'search search index="hariindex"'
kwargs_normalsearch = {"exec_mode": "normal"}
job = service.jobs.create(searchquery_normal, **kwargs_normalsearch)
print(job.results(output_mode='json'))
# Get the results and display them
for result in results.JSONResultsReader(job.results(output_mode='json')):
    print (result)

job.cancel()   
# sys.stdout.write('\n')
