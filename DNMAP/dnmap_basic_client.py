import logging
import os
import time
import sys
from dxlclient.service import ServiceRegistrationInfo
from dxlclient.client import DxlClient
from dxlclient.client_config import DxlClientConfig
from dxlclient.message import Message, Request, Response
from dxlclient.callbacks import RequestCallback, ResponseCallback

new_topic = "/nmap/service/dnmap/scan_request"
ne_topic="/nmap/service/dnmap/receive_response"
SERVICE_NAME="/nmap/service/dnmap"

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
           
    # Create the scan request
	req = Request(new_topic)

        #Populate the request payload with nmap commands to be run
	req.payload = "10.0.0.149 -A -sV -sS -O".encode()
	res = client.sync_request(req)
	print "sent the query"
	res = res.payload.decode(encoding="UTF-8")
	print res
    

        #Create "Scan Result" incoming request callback to display scan results
        class ScanResultCallback(RequestCallback):
        	def on_request(self, request):
            
                        #Extract information from request. Here the query is actually the nmap scan results.
        	        query = request.payload.decode(encoding="UTF-8")
			logger.info("Service received request payload: " + query)
			print query
			#extra stuff
			response=Response(request)
			response.payload="Scan Complete! ".encode()
			client.send_response(response)
	    
	    
        #Create service registration object
        info = ServiceRegistrationInfo(client, SERVICE_NAME)

        #Add a topic for the service to respond to
        info.add_topic(ne_topic, ScanResultCallback())
    
        #Register the service with the fabric (wait up to 10 seconds for registration to complete)
        client.register_service_sync(info, 10)

        logger.info("Weather service is running...")

    # Wait forever
        while True:
        	time.sleep(60)

