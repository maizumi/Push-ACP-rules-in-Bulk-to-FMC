import requests
import csv
import json
from requests.auth import HTTPBasicAuth
from getpass import getpass
import os
from flask import Flask, render_template, request, redirect, url_for, send_from_directory, session
from werkzeug.utils import secure_filename

app = Flask(__name__)

UPLOAD_FOLDER = './uploads'
ALLOWED_EXTENSIONS = set(['csv'])
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.route('/', methods=['GET'])
def login():
    return render_template("index2.html")

def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS


@app.route('/send', methods=['GET', 'POST'])
def send():
    if request.method == 'POST':
        csv_file = request.files['csv_file']
        if csv_file and allowed_file(csv_file.filename):
            filename = secure_filename(csv_file.filename)
            csv_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            csv_url = app.config['UPLOAD_FOLDER'] + '/' + filename
            abspath  = os.path.abspath(filename)
            
            fmc_ip = request.form.get('fmc_ip')
            fmc_username = request.form.get('fmc_username')
            fmc_password = request.form.get('fmc_password')
            fmc_policy_name = request.form.get('fmc_policy_name')
         
            address = fmc_ip
            username = fmc_username
            password = fmc_password
            policyname = fmc_policy_name
                        
            api_uri = "/api/fmc_platform/v1/auth/generatetoken"
            url = "https://" + address + api_uri
            
            response_token = requests.request("POST", url, verify=False, auth=HTTPBasicAuth(username, password))
            
            accesstoken = response_token.headers["X-auth-access-token"]
            refreshtoken = response_token.headers["X-auth-refresh-token"]
            DOMAIN_UUID = response_token.headers["DOMAIN_UUID"]
            
            headers = {'Content-Type': 'application/json', 'x-auth-access-token': accesstoken}

            csvFilePath = csv_url
            
            access_policy_data = """
            {
                "type": "AccessPolicy",
                "name": "AccessControlPolicy(made by tool)",
                "defaultAction": {
                    "action": "PERMIT"
                }
            }
            """

            a = """
            {
                "type": "AccessPolicy",
            """
            aa = "    "
            b1 = "name"
            b2 = ": "
            b3 = policyname
            b4 = ","
            
            ba = json.dumps(b1)
            
            bb = json.dumps(b3)
            
            d = aa+ba+b2+bb+b4

            c = """
                "defaultAction": {
                    "action": "PERMIT"
                }
            }
            """
            z = a+d+c
            print(z)
                   
            if fmc_policy_name == "":
                #access control policy
                access_policy_api_uri = "/api/fmc_config/v1/domain/" + DOMAIN_UUID +  "/policy/accesspolicies"
                access_policy_url = "https://" + address + access_policy_api_uri
                response_acp = requests.request("POST", access_policy_url, headers=headers, data=access_policy_data, verify=False)
                responsemessage_acp = response_acp.json()
                containeruuid = responsemessage_acp['id']
            else:
                #access control policy
                access_policy_api_uri = "/api/fmc_config/v1/domain/" + DOMAIN_UUID +  "/policy/accesspolicies"
                access_policy_url = "https://" + address + access_policy_api_uri
                response_acp = requests.request("POST", access_policy_url, headers=headers, data=z, verify=False)
                responsemessage_acp = response_acp.json()
                print(responsemessage_acp)
                containeruuid = responsemessage_acp['id']
                        
            #access control policy
            #access_policy_api_uri = "/api/fmc_config/v1/domain/" + DOMAIN_UUID +  "/policy/accesspolicies"
            #access_policy_url = "https://" + address + access_policy_api_uri
            #response_acp = requests.request("POST", access_policy_url, headers=headers, data=access_policy_data, verify=False)
            #responsemessage_acp = response_acp.json()
            #containeruuid = responsemessage_acp['id']
            
            ###############objects検索####################################
            #Network Objects
            network_objects_api_uri = "/api/fmc_config/v1/domain/" + DOMAIN_UUID +  "/object/networks"
            network_objects_url = "https://" + address + network_objects_api_uri
            network_objects = requests.get(network_objects_url, headers=headers, verify=False)
            network_objects_all = network_objects.json()
                        
            #Network Host
            network_hosts_api_uri = "/api/fmc_config/v1/domain/" + DOMAIN_UUID +  "/object/hosts"
            network_hosts_url = "https://" + address + network_hosts_api_uri
            network_hosts = requests.get(network_hosts_url, headers=headers, verify=False)
            network_hosts_all = network_hosts.json()
            
            #Network Range
            network_ranges_api_uri = "/api/fmc_config/v1/domain/" + DOMAIN_UUID +  "/object/ranges"
            network_ranges_url = "https://" + address + network_ranges_api_uri
            network_ranges = requests.get(network_ranges_url, headers=headers, verify=False)
            network_ranges_all = network_ranges.json()
            
            all_of_objects = network_hosts_all["items"] + network_objects_all["items"] + network_ranges_all["items"]
            
            	
            ###############objects検索####################################
            
            ###security zone###
            security_zone_uri = "/api/fmc_config/v1/domain/" + DOMAIN_UUID +  "/object/securityzones"
            security_zone_url = "https://" + address + security_zone_uri
            security_zone = requests.get(security_zone_url, headers=headers, verify=False)
            security_zone_lists = security_zone.json()
                        
            result = []
            with open(csvFilePath, encoding='utf-8-sig') as f:
            	reader = csv.DictReader(f)
            	for r in reader:
            		srczone = r["sourceZones"]
            		dstzone = r["destinationZones"]
            		sourcenwobject = r["sourceNetworksObject"]
            		destnwobject = r["destinationNetworksObject"]
            		for dct in all_of_objects:
            			NetworkObject = str(dct['name'])
            			NetworkObjectId = str(dct['id'])
            			NetworkObjectType = str(dct['type'])
            			if NetworkObject == sourcenwobject:
            				sourceObjectUUID = NetworkObjectId
            				sourceObjectType = NetworkObjectType
            			if NetworkObject == destnwobject:
            				destObjectUUID = NetworkObjectId
            				destObjectType = NetworkObjectType
            		for dct in security_zone_lists["items"]:
            			zonename = str(dct['name'])
            			if zonename == srczone:
            				srczoneUUID = str(dct['id'])
            			if zonename == dstzone:
            				dstzoneUUID = str(dct['id'])

            		result.append({
            			"action": r["action"],
            			"enabled": r["enabled"],
            			"type": "AccessRule",
            			"name": r["rulename"],
            			"sendEventsToFMC": r["sendEventsToFMC"],
            			"logBegin": r["logBegin"],
            			"logEnd": r["logEnd"],
            			"sourceZones":{
            				"objects": [
            				{
            					"name": r["sourceZones"],
            					"id": srczoneUUID,
            					"type": "SecurityZone",
            				}
            				]
            			},
            			"destinationZones":{
            				"objects": [
            				{
            					"name": r["destinationZones"],
            					"id": dstzoneUUID,
            					"type": "SecurityZone",
            					}
            				]
            			},
            			"sourceNetworks": {
            				"objects": [
            				{
            					"name": r["sourceNetworksObject"],
            					"id": sourceObjectUUID,
            					"type": sourceObjectType,
            					}
            				]
            			},
            			"destinationNetworks": {
            				"objects": [
            				{
            					"name": r["destinationNetworksObject"],
            					"id": destObjectUUID,
            					"type": destObjectType,
            				}
            				]
            			},
            			#"sourcePorts": {
            			#	"literals": [
            			#	{
            			#		"type": "PortLiteral",
            			#		"port": r["sourcePort_number"],
            			#		"protocol": r["sourcePort_protocol"],
            			#	}
            			#	]
            			#},
            			"destinationPorts": {
            				"literals": [
            				{
            					"type": "PortLiteral",
            					"port": r["destinationPort_number"],
            					"protocol": r["destinationPort_protocol"],
            				}
            				]
            			},
            		})
            json_result = json.dumps(result)
            json_result2 = json_result.replace('"TRUE"', 'true')
    			
            if result != []:
                #access rule(bulk)
                access_rule_api_uri_bulk = "/api/fmc_config/v1/domain/" + DOMAIN_UUID +  "/policy/accesspolicies/" + containeruuid +  "/accessrules?bulk=true"
                access_rule_url_bulk = "https://" + address + access_rule_api_uri_bulk
                response_acp_rule_bulk = requests.request("POST", access_rule_url_bulk, headers=headers, data=json_result2, verify=False)
                responsemessage_acp_rule_bulk = response_acp_rule_bulk.json()

            else:
                print("Please Validate that the CSV file provided is correct or at correct location")
    			
            if response_acp_rule_bulk.status_code == 201 or response_acp_rule_bulk.status_code == 202:
                print("ACP rules successfully pushed")
            else:
                print("ACP rules creation failed")
            
            return render_template('index2.html', csv_url=csv_url)
        else:
            return ''' <p>許可されていない拡張子です</p> '''
    else:
        return redirect(url_for('index2'))

if __name__ == '__main__':
    app.debug = True
    app.run()



