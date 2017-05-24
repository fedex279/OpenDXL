import logging
import os
import sys
import time
import urllib2
import requests
import json
import subprocess

from dxlclient.callbacks import RequestCallback
from dxlclient.client import DxlClient
from dxlclient.client_config import DxlClientConfig
from dxlclient.message import ErrorResponse, Response
from dxlclient.service import ServiceRegistrationInfo

SERVICE_NAME="/nmap/service/dnmap"
broadcast_topic = "/nmap/service/dnmap/send_broadcast_request"

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

    # Create incoming request callback to receive the broadcasts sent by the moderator
	class RecieveBroadcastCallback(RequestCallback):
	        def on_request(self, request):
            		try:
                # Extract information from request
            			query = request.payload.decode(encoding="UTF-8")
                		logger.info("Service received request payload: " + query)

                # nmap command construction
				command = "nmap " + query
				command = command.split()
				test = subprocess.Popen(command, stdout = subprocess.PIPE)
				output = test.communicate()[0]
				print output
                
		
                # Create the response message
                		response = Response(request)
                # Populate the response payload
                		response.payload = output.encode(encoding="UTF-8")
                # Send the response
                		client.send_response(response)

			except Exception as ex:
                		print str(ex)
                # Send error response
                		client.send_response(ErrorResponse(request, error_message=str(ex).encode(encoding="UTF-8")))

    # Create service registration object
	info = ServiceRegistrationInfo(client, SERVICE_NAME)

    # Add a topic for the service to respond to
	info.add_topic(broadcast_topic, RecieveBroadcastCallback())

    # Register the service with the fabric (wait up to 10 seconds for registration to complete)
	client.register_service_sync(info, 10)

	logger.info("Dnmap service is running...")

    # Wait forever
        while True:
        	time.sleep(60)
