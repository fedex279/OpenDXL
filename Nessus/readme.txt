#Nessus using DXL

##Invoker
The Nessus Inokver can be executed from any client that can run Python.  In its current iteration, it will run a basic scan on target(s) identified via CLI:
    nessus_invoker.py -t <IP>|<CIDR>
When the Invoker is run, it sends the scan type, and IP/CIDR to the Wrapper via DXL, and the Wrapper delivers a complete request to Nessus.  After the scan is complete, the client will export the results to an xml file.

##Wrapper
The Wrapper allows Nessus to be invoked by clients on DXL by submitting a message to "/tenable/service/nessus/newscan". The wrapper will build a full API call to the Nessus server and submit the reuqest.  When the scan is complete, the result will be collected and sent back to the requesting client.  In its current iteration, options are provided in the script, and muslt be filled out with your environment details; URL, username, password, API Key, and secret key must be replaced (along with the angle brackets which indicate a field that must be replaced).

url = '<URL of Nessus here>'
verify = False
username = '<your username here>'
password = '<your password here>'
token =''
#API keys and secret keys are obtained from Nessus user account information
API_KEYS = 'accessKey=<API key here>'
secret_key = '<your key here>'
