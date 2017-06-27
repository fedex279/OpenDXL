/* ===================================================
 * Copyright 2017 Uha Durbha
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ========================================================== */



import json
import logging
import os
import sys
import requests

from nessus_common import *
from dxlclient.client import DxlClient
from dxlclient.client_config import DxlClientConfig
from dxlclient.message import Message, Request
from bs4 import BeautifulSoup
from requests.packages.urllib3.exceptions import InsecureRequestWarning


#bypasses the certificate related warnings while using requests
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

#define the dxl service names
service_name = "/tenable/service/nessus"
service_newscan = service_name + "/new_scan"


# Import common logging and configuration
sys.path.append(os.path.dirname(os.path.abspath(__file__)) + "/..")
from common import *

# Configure local logger
logging.getLogger().setLevel(logging.INFO)
logger = logging.getLogger(__name__)

# Create DXL configuration from file
config = DxlClientConfig.create_dxl_config_from_file(CONFIG_FILE)

# Create the client
with DxlClient(config) as client:

    # Connect to the fabric
	client.connect()

	req = Request(service_newscan)
	query = "{0} {1}".format(target, scan_type)
	print query
        req.payload = query.encode()

        #Send the request and wait for a response (synchronous)
        res = client.sync_request(req)
   
	#decode the received response
        response = res.payload.decode(encoding="UTF-8")
        soup = BeautifulSoup(response,'lxml')
	print "Scan results ready"
	#writing scan results to xml file
	filename= "nessus_report.xml"
	print('Saving scan results to {0}.'.format(filename))
    	with open(filename, 'w') as f:
        	f.write(response)
        	
	#displaying the scan results
	syn = soup.find_all('synopsis')
	out = soup.find_all('plugin_output')
	sol = soup.find_all('solution')
	name = soup.find_all('plugin_name')
	for x in range(0,len(syn),1):
		print name[x].string
		print "Synopsis :{0}".format(syn[x].string)
		print "Output :{0}".format(out[x].string)
		print "Solution :{0}".format(sol[x].string)
		print "\n"
		
	#additionally searching for desired attributes
	attr= raw_input("Enter attribute to look for :  ")
	attr = soup.find_all(attr)
	for x in range(0,len(attr),1):
		print attr[x].string
	 
    
