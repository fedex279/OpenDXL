# OpenDXL
This repository consists of two use cases using OpenDXL.

## Nessus
In an automation context, making a vulnerability scanner available in a pub/sub model means that clients that are authenticated on the fabric can request a vulnerability scan, and dont need to have the necessary API information (IP, username/password or API key), and the invoker of the request doesnt need to have access to port 8834 (or wherever Nessus is hosted).

**nessus_invoker.py**

The invoker acts as a client which can initiate a scan request to Nessus; it simply needs to send the target information, and report type as a message on the DXL topic "/tenable/service/nessus".  The client receives the response back when the scan is complete and saves the report in an XML format, and outputs key data to stdout.

**nessus_wrapper.py**

The wrapper is a DXL service, and handles all API functionality for scan requests coming in on the DXL topic "/tenable/service/nessus". When a request comes from the invoker, the wrapper makes the appropriate API calls to the Nessus server, and returns the report to the requesting client (invoker) when the task is complete.
	
## dnmap 
DOCUMENTATION COMING SOON

Files in project are:

- **dnmap_basic_client.py**

- **dnmap_moderator.py**

- **dnmap_scanner.py**

# Prerequisites
Both of these projects use OpenDXL, and as such have some prerequisites:
- McAfee [OpenDXL](https://www.mcafee.com/us/developers/open-dxl/index.aspx) python Client
  - Each system running the scripts will need the opendxl client and an openssl certificate.  Please see their documentation for configuration on [their Wiki](https://opendxl.github.io/opendxl-client-python/pydoc/dxlclient.client_config.html).  
    - This code reads from a config file using the create_dxl_config_from_file, so be sure to build a config file.  
    - This code also uses [common.py](https://github.com/opendxl/opendxl-client-python/blob/master/examples/common.py) to setup logging and read the config file, so please download the file and put it in the same directory as the script you are running, or in its parent directory.
- McAfee Data Exchange Layer Broker v3.x+: MFE DXL Fabric Message broker
- McAfee ePolicy Orchestrator v5.3+: Single console for Endpoint Security Management
