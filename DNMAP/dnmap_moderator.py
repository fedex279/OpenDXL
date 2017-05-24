import logging
import os
import sys
import time
import urllib2
import requests
import json

from dxlclient.callbacks import RequestCallback, ResponseCallback
from dxlclient.client import DxlClient
from dxlclient.client_config import DxlClientConfig
from dxlclient.message import ErrorResponse, Response, Request, Message
from dxlclient.service import ServiceRegistrationInfo

# Import common logging and configuration
sys.path.append(os.path.dirname(os.path.abspath(__file__)) + "/..")
from common import *

ne_topic="/nmap/service/dnmap/receive_response"
SERVICE_NAME="/nmap/service/dnmap"
broadcast_topic = "/nmap/service/dnmap/send_broadcast_request"
new_topic = "/nmap/service/dnmap/scan_request"

# Configure local logger
logging.getLogger().setLevel(logging.INFO)
logger = logging.getLogger(__name__)

config = DxlClientConfig.create_dxl_config_from_file(CONFIG_FILE)

# Create the client
with DxlClient(config) as client:

    # Connect to the fabric
        client.connect()

    #
    # Register the service
    #
        class BroadcastCallback(ResponseCallback):        
		def on_response(self, response):
	        	print "received response"
	        	scan_output = response.payload.decode(encoding="UTF-8")
	    		print scan_output
	    		time.sleep(30)
	    		re=Request(ne_topic)
	    		re.payload = scan_output.encode()
	    		client.async_request(re,ScanResultCallback())
	    
    	class ScanResultCallback(ResponseCallback):        
		def on_response(self, response):
	    		print "done"
	    
	    
		
    # Create "Scan Request" incoming request callback
    	class ScanRequestCallback(RequestCallback):
        	def on_request(self, request):
            
                # Extract information from request
                	query = request.payload.decode(encoding="UTF-8")
			print request.destination_topic
			print request.message_id
                	logger.info("Service received request payload: " + query)
			print query
			re = Response(request)
			re.payload="Waiting for scan output".encode()
			client.send_response(re)
                # Send the query to the different scanners
			req = Request(broadcast_topic)
			req.payload = query.encode()
			response=client.async_request(req, BroadcastCallback())
			print response
	
                
	    
    # Create service registration object
    	info = ServiceRegistrationInfo(client, SERVICE_NAME)

    # Add a topic for the service to respond to
    	info.add_topic(new_topic, ScanRequestCallback())
    
    # Register the service with the fabric (wait up to 10 seconds for registration to complete)
    	client.register_service_sync(info, 10)

    	logger.info("Weather service is running...")

    # Wait forever
    	while True:
        	time.sleep(60)
