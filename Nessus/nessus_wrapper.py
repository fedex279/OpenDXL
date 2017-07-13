#============================================================================
#Copyright 2017 Uha Durbha
#
#Licensed under the Apache License, Version 2.0 (the "License");
#you may not use this file except in compliance with the License.
#You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
#Unless required by applicable law or agreed to in writing, software
#distributed under the License is distributed on an "AS IS" BASIS,
#WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#See the License for the specific language governing permissions and
#limitations under the License.
#============================================================================

import logging
import os
import sys
import time
import webbrowser
import urllib2
import urllib3
import json
import requests
import subprocess

from dxlclient.callbacks import RequestCallback
from lxml import etree
from dxlclient.client import DxlClient
from dxlclient.client_config import DxlClientConfig
from dxlclient.message import ErrorResponse, Response
from dxlclient.service import ServiceRegistrationInfo
from requests.packages.urllib3.exceptions import InsecureRequestWarning
#to bypass insecure request warning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


url = 'https://localhost:8834'
verify = False
username = 'username'
password = 'password'
token =''
#API keys and secret keys are obtained from Nessus user account information
API_KEYS = 'accessKey=(access key for your Nessus account)'
secret_key = '(secret key for the Nessus account)'
#define dxl topics for the service
service_name = "/tenable/service/nessus"
service_newscan = service_name + "/new_scan"
#define http request parameters to be set when sending http requests to remote nessus client
headers = {'X-Cookie': 'token={0}'.format(token),
		'X-ApiKeys': '{0}; secretKey={1}'.format(API_KEYS,secret_key),
               'content-type': 'application/json','connection': 'keep-alive'}


# Import common logging and configuration
sys.path.append(os.path.dirname(os.path.abspath(__file__)) + "/..")
from common import *

# Configure local logger
logging.getLogger().setLevel(logging.INFO)
logger = logging.getLogger(__name__)

# Create DXL configuration from file
config = DxlClientConfig.create_dxl_config_from_file(CONFIG_FILE)

#function to get the status of the ongoing Nessus scan. If status is "complete", scan results are available to download 
def status(sid, hid):
        ids = {'history_id': hid}	
	history_url = url + '/scans/{0}'.format(sid)
	r6= requests.get(history_url, params = json.dumps(ids), headers=headers,verify=verify)
	z=r6.json()
	za = z['info']
	return za['status']
#Function to find out if scan results are ready to be exported in specified file format
def export_status(scan_id, file_id):		
	urls = url + '/scans/{0}/export/{1}/status'.format(scan_id, file_id)
	r=requests.get(urls, params=None, headers=headers, verify=verify)
	data=r.json()
	return data['status'] == 'ready'


# Create the client
with DxlClient(config) as client:
        client.connect()
	class WeatherCallback(RequestCallback):
		def on_request(self, request):
			#decode the received query/request
			query = request.payload.decode(encoding="UTF-8")
			q=query.split()
			logger.info("Service received request payload: " + query)

                        #separating type of scan and target
			target=q[0]
			type_of_scan = query.replace(target,'')
			type_of_scan=type_of_scan.strip()
			print "performing following scan : " + type_of_scan

			#start nessus
			os.system("/etc/init.d/nessusd start")
                        #the following two lines are only for initialisation of Nessus if using
			#Nessus for the first time after powering on the system
			webbrowser.open(url)
			time.sleep(120)
			
			#login to nessus
			print "logging in"
			login_url = url + "/session"
			login = {'username': username, 'password': password}
			s = requests.Session()
			s.post(login_url, data=json.dumps(login), headers=headers, verify=verify)
			

			#get all policies and their id
			print "getting policy information"
			get_policy_url = url + "/editor/policy/templates"
			r2=s.get(get_policy_url, params=None, headers=headers, verify=verify)
			data = r2.json()
			policies = dict((p['title'], p['uuid']) for p in data['templates'])
			policy_id = policies[str(e)]

                        #uncomment the following code to choose from existing policies
                        #variable choose_policy must be updated in the config file
			"""To choose from existing policies:
			n=url+"/policies"
			a=s.get(n,params=None, headers=headers, verify=verify)
			a=a.json()
			policies = dict((p['name'], p['template_uuid']) for p in a['policies'])
			policy_id = policies[choose_policy]
			"""				
			
			#adding a new scan
			scan = {'uuid': str(policy_id),
            			'settings': {
                		'name': 'new scan',
                		'description': 'dxl nessus scan',
                		'text_targets': str(target)}
            			}
			
			scan_url = url +"/scans"
			r3 = s.post(scan_url, data=json.dumps(scan), headers=headers, verify=verify)
			scan = r3.json()
			scan_info = scan['scan']
			scan_id = scan_info['id']
			
			
			#launching scan on target
			print('launching scan')
			launch_url = url + '/scans/{0}/launch'.format(scan_id)
			r4 = s.post(launch_url, data = None, headers=headers, verify=verify)			
			x=r4.json()
			scan_uuid = x['scan_uuid']
			
			
			#getting scan history			
			history_url = url + '/scans/{0}'.format(scan_id)
			r5 = s.get(history_url, params = None, headers=headers, verify=verify)
			y=r5.json()
			history_ids = dict((h['uuid'], h['history_id']) for h in y['history']) 
			history_id = history_ids[scan_uuid]
			
			#checking scan status
			ids = {'history_id': history_id}
			r6= s.get(history_url, params = ids, headers=headers,verify=verify)
			z=r6.json()
			za=z['info']

		
			while status(scan_id, history_id) !='completed':
				time.sleep(5)
				
				
			#exporting scan after it's complete
			print('Exporting complete scan')
			a = {'history_id': history_id,
            			'format': 'nessus'} #default is nessus

			export_url = url + '/scans/{0}/export'.format(scan_id)
			r9=s.post(export_url, data=json.dumps(a), headers=headers, verify=verify)
			export= r9.json()
			file_id = export['file']
			status_url = url + '/scans/{0}/export/{1}/status'.format(scan_id, file_id)
			r7=s.get(status_url, params=None, headers=headers, verify=verify)
			b=r7.json()
			while export_status(scan_id, file_id) is False:
        			time.sleep(5)
        			
			
			#downloading the scan results
			download_url = url + '/scans/{0}/export/{1}/download'.format(scan_id, file_id)
			r8 = s.get(download_url, params=None, headers=headers, verify=verify)
			content=r8.content
			
			#saving results to a file locally (can be omitted)
			filename= "nessus_report{0}.xml".format(scan_id)
			print('Saving scan results to {0}.'.format(filename))
    			with open(filename, 'w') as f:
        			f.write(content)
        			
			#sending response on the topic
			with open(filename, 'r') as f:
        			lines=f.read()
			
			response=Response(request)
			response.payload = lines.encode(encoding="UTF-8")
			client.send_response(response)
			
			
        				
        info = ServiceRegistrationInfo(client, service_name)
	info.add_topic(service_newscan, WeatherCallback())
	client.register_service_sync(info,10)
	logger.info("service is running...")
	while True:
		time.sleep(60)
			
