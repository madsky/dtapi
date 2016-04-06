#!/usr/bin/python

def dtapicall(appliance, query, publickey, privatekey, timemod=0, verifySSL=False):
	"""Returns JSON-formatted data from the Darktrace <appliance> specified, using the <query> specified, and the <publickey> and <privatekey> supplied
	
	<appliance> is the full URL of the appliance, for example 'https://10.1.2.3'
	<query> is the API query you are passing to the appliance, for example '/metrics'
	<publickey> is the public key which is provided from the Darktrace appliance (provided by the reseller)
	<privatekey> is the private key which is provided from the Darktrace appliance (provided by the reseller)
	
	optional <timemod> allows you to modify the current time passed (default=0) to the API to allow for timezone differences, e.g., passing 59 will add 59 minutes to the time, -59 will take off 59 minutes.
	optional <verifySSL> allow you to ignore cert errors (default=False) when making the call

	If successful it returns an object containing JSON-formatted data matching your query.
	
	@leighhall / madsky.co.uk
	Version: 1.0 / Aug 2015

	"""
	
	import datetime
	import hmac
	import hashlib
	import requests

	#today = datetime.datetime.today()
	today = datetime.datetime.utcnow() 
	today = today + datetime.timedelta(minutes=timemod)
	format = "%Y%m%dT%H%M%S"
	dt = today.strftime(format)

	hmac = hmac.new(privatekey, query+"\n"+publickey+"\n"+dt, hashlib.sha1)

	payload = {
		'DTAPI-Token': publickey,
		'DTAPI-Date': dt,
		'DTAPI-Signature': hmac.hexdigest()
	}

	r = requests.get(appliance+query, headers=payload, verify=verifySSL)
	ret = r.json()

	return ret
