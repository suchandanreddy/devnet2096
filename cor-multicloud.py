#! /usr/bin/env python

import os
import tabulate
import requests
import click
import json
import sys
import yaml

requests.packages.urllib3.disable_warnings()

from requests.packages.urllib3.exceptions import InsecureRequestWarning

vmanage_host = os.environ.get("vmanage_host")
vmanage_port = os.environ.get("vmanage_port")
vmanage_username = os.environ.get("vmanage_username")
vmanage_password = os.environ.get("vmanage_password")

if vmanage_host is None or vmanage_port is None or vmanage_username is None or vmanage_password is None:
    print("For Windows Workstation, vManage details must be set via environment variables using below commands")
    print("set vmanage_host=198.18.1.10")
    print("set vmanage_port=8443")
    print("set vmanage_username=admin")
    print("set vmanage_password=admin")
    print("For MAC OSX Workstation, vManage details must be set via environment variables using below commands")
    print("export vmanage_host=198.18.1.10")
    print("export vmanage_port=8443")
    print("export vmanage_username=admin")
    print("export vmanage_password=admin")
    exit()

class Authentication:

    @staticmethod
    def get_jsessionid(vmanage_host, vmanage_port, username, password):
        api = "/j_security_check"
        base_url = "https://%s:%s"%(vmanage_host, vmanage_port)
        url = base_url + api
        payload = {'j_username' : username, 'j_password' : password}
        
        response = requests.post(url=url, data=payload, verify=False)
        print(response.text)
        try:
            cookies = response.headers["Set-Cookie"]
            jsessionid = cookies.split(";")
            return(jsessionid[0])
        except:
            click.echo("No valid JSESSION ID returned\n")
            exit()
       
    @staticmethod
    def get_token(vmanage_host, vmanage_port, jsessionid):
        headers = {'Cookie': jsessionid}
        base_url = "https://%s:%s"%(vmanage_host, vmanage_port)
        api = "/dataservice/client/token"
        url = base_url + api      
        response = requests.get(url=url, headers=headers, verify=False)
        if response.status_code == 200:
            return(response.text)
        else:
            return None


Auth = Authentication()
jsessionid = Auth.get_jsessionid(vmanage_host,vmanage_port,vmanage_username,vmanage_password)
token = Auth.get_token(vmanage_host,vmanage_port,jsessionid)

if token is not None:
    header = {'Content-Type': "application/json",'Cookie': jsessionid, 'X-XSRF-TOKEN': token}
else:
    header = {'Content-Type': "application/json",'Cookie': jsessionid}

base_url = "https://%s:%s/dataservice"%(vmanage_host, vmanage_port)

@click.group()
def cli():
    """Command line tool for vManage Templates and Policy Configuration APIs.
    """
    pass

@click.command()
@click.option("--input_yaml", help="AWS Account API Keys")
def associate_account(input_yaml):
    """ Associate the cloud service provider account                             
        \nExample command: ./cor-multicloud.py associate-account --input_yaml aws-config.yaml
    """
    click.secho("Associating the cloud service provider account")

    with open(input_yaml) as f:
        config = yaml.safe_load(f.read())

    url = base_url + "/multicloud/accounts"

    payload = {
                "accountName": config["aws_accountname"],
                "cloudType": "AWS",
                "description": "",
                "cloudGatewayEnabled": "true",
                "awsKeyCredentials": {
                        "apiKey": config["aws_apiKey"],
                        "secretKey": config["aws_secretkey"]
                    }
            }

    response = requests.post(url=url, headers=header, data=json.dumps(payload),verify=False)

    if response.status_code == 200:
        #accountId = response.json()['accountId']
        accountId = "<Account ID>"
        regionList = response.json()['regionList']
    else:
        print("Failed to associate cloud provider account")
        exit()

    headers = ["Account Id", "Region List"]
    table = list()
    tr = [accountId, regionList]
    table.append(tr)
    
    try:
        click.echo(tabulate.tabulate(table, headers, tablefmt="fancy_grid"))
    except UnicodeEncodeError:
        click.echo(tabulate.tabulate(table, headers, tablefmt="grid"))

@click.command()
def multicloud_globalsettings():
    """ Configure Multi Cloud Global Settings.                              
        \nExample command: ./cor-multicloud.py multicloud-globalsettings
    """
    click.secho("Configuring Multi Cloud Global Settings")

    url = base_url + "/multicloud/settings/global"

    payload =  {
                    "cloudType": "AWS",
                    "cloudGatewaySolution": "tgw_tvpc",
                    "softwareImageId": "Cisco-C8K-17.06.02-89aa2e04-79cb-44c1-981d-160b56247c98",
                    "instanceSize": "c5n.large",
                    "ipSubnetPool": "192.168.0.0/24",
                    "cgwBgpAsnOffset": 64520,
                    "intraTagComm": True,
                    "programDefaultRoute": True,
                    "mapTvpc": True,
                    "tunnelType": "ipsec"
            }

    response = requests.post(url=url, headers=header, data=json.dumps(payload),verify=False)
    
    if response.status_code == 200:
        print("Configured/updated Multi Cloud Global Settings")

    else:
        print("Failed to configure Multi Cloud Global Settings")
        exit()


@click.command()
def discover_hostvpc():
    """ Discover AWS Host VPCs.                              
        \nExample command: ./cor-multicloud.py discover-hostvpc
    """
    click.secho("Discovering Host VPCs in associated Cloud Service Provider account")

    url = base_url + "/multicloud/hostvpc?cloudType=AWS"

    response = requests.get(url=url, headers=header, verify=False)

    if response.status_code == 200:
        items = response.json()['data']
    
    else:
        print("Failed to discover host vpcs")
        exit()


    headers = ["Account Name", "Region", "Host VPC ID", "Host VPC Name"]
    table = list()

    for item in items:
        tr = [item['accountName'], item['region'], item['hostVpcId'], item['hostVpcName']]
        table.append(tr)
    try:
        click.echo(tabulate.tabulate(table, headers, tablefmt="fancy_grid"))
    except UnicodeEncodeError:
        click.echo(tabulate.tabulate(table, headers, tablefmt="grid"))


@click.command()
@click.option("--input_yaml", help="AWS VPC Tag names")
def tag_hostvpc(input_yaml):
    """ Add Tag to Host VPC.                              
        \nExample command: ./cor-multicloud.py tag-hostvpc
    """
    click.secho("Adding Tag to Host VPC")

    url = base_url + "/multicloud/hostvpc/tags?cloudType=AWS"

    with open(input_yaml) as f:
        config = yaml.safe_load(f.read())
    
    tag_name = config["tag_name"]
    host_vpc_name = config["host_vpc_name"]

    payload = {
                    "tagName": tag_name,
                    "interconnectTag": False,
                    "hostVpcs": [
                                    {
                                        "accountId": config["aws_accountid"],
                                        "accountName": config["aws_accountname"],
                                        "region": "us-west-2",
                                        "cloudType": "AWS",
                                        "hostVpcId": config["host_vpc_id"],
                                        "hostVpcName": host_vpc_name,
                                        "id": config["host_vpc_id"],
                                        "label": config["host_vpc_id"]
                                    }
                                ]
                }


    response = requests.post(url=url, headers=header, data=json.dumps(payload), verify=False)

    if response.status_code == 200:
        process_id = response.json()["id"]
    else:
        click.echo("\nFailed to attach Tag to Host VPC" + str(response.text))     
        exit()

    api_url = '/device/action/status/' + process_id  

    url = base_url + api_url

    while(1):
        tag_status_res = requests.get(url,headers=header,verify=False)
        if tag_status_res.status_code == 200:
            tag_push_status = tag_status_res.json()
            if tag_push_status['summary']['status'] == "done":
                if 'Success' in tag_push_status['summary']['count']:
                    click.echo("\nSuccessfully associated Tag %s to Host VPC %s"%(tag_name,host_vpc_name))
                elif 'Failure' in tag_push_status['summary']['count']:
                    click.echo("\nFailed to associate Tag %s to Host VPC %s"%(tag_name,host_vpc_name))
                break



@click.command()
@click.option("--input_yaml", help="C8kv uuids")
def add_cloudgateway(input_yaml):
    """ Add Cloud Gateway.                              
        \nExample command: ./cor-multicloud.py add-cloudgateway --input_yaml sandbox-config.yaml
    """
    click.secho("Adding Cloud Gateway")

    url = base_url + "/multicloud/cloudgateway"

    with open(input_yaml) as f:
        config = yaml.safe_load(f.read())

    payload = {
                    "cloudType": "AWS",
                    "accountId": config["aws_accountid"],
                    "region": "us-west-2",
                    "cloudGatewayName": "Cloud-TME-CGW",
                    "devices": [
                                    config["c8kv1-uuid"],
                                    config["c8kv2-uuid"]
                                ],
                    "description": ""
              }


    response = requests.post(url=url, headers=header, data=json.dumps(payload), verify=False)
    if response.status_code == 200:
        process_id = response.json()["id"]
    else:
        click.echo("Failed to create cloud gateway" + str(response.text))
        exit()     

    api_url = '/device/action/status/' + process_id  

    url = base_url + api_url

    while(1):
        tag_status_res = requests.get(url,headers=header,verify=False)
        if tag_status_res.status_code == 200:
            tag_push_status = tag_status_res.json()
            if tag_push_status['summary']['status'] == "done":
                if 'Success' in tag_push_status['summary']['count']:
                    click.echo("\nSuccessfully created cloud gateway")
                elif 'Failure' in tag_push_status['summary']['count']:
                    click.echo("\nFailed to create cloud gateway")
                break


@click.command()
def add_cloudconnectivity():
    """ Enable Cloud Connectivity                              
        \nExample command: ./cor-multicloud.py add-cloudconnectivity
    """
    click.secho("Adding Intent mapping to enable Cloud Connectivity")

    url = base_url + "/multicloud/map?cloudType=AWS"

    payload = {
                "cloudType": "AWS",
                "connMatrix": [
                    {
                        "srcType": "vpn",
                        "srcId": "10",
                        "destType": "tag",
                        "destId": "VPC1-Eng1",
                        "conn": "enabled"
                    },
                    {
                        "srcType": "tag",
                        "srcId": "VPC1-Eng1",
                        "destType": "vpn",
                        "destId": "10",
                        "conn": "enabled"
                    }
                ]
            }


    response = requests.post(url=url, headers=header, data=json.dumps(payload), verify=False)
    if response.status_code == 200:
        process_id = response.json()["id"]
    else:
        click.echo("Failed to create cloud connectivity" + str(response.text))
        exit()     

    api_url = '/device/action/status/' + process_id  

    url = base_url + api_url

    while(1):
        tag_status_res = requests.get(url,headers=header,verify=False)
        if tag_status_res.status_code == 200:
            tag_push_status = tag_status_res.json()
            if tag_push_status['summary']['status'] == "done":
                if 'Success' in tag_push_status['summary']['count']:
                    click.echo("\nSuccessfully created cloud gateway")
                elif 'Failure' in tag_push_status['summary']['count']:
                    click.echo("\Failed to create cloud gateway")
                break



@click.command()
def cloud_gateway_list():
    """ Retrieve cloud gateways list.                      
        \nExample command: ./cor-multicloud.py cloud-gateway-list
    """
    click.secho("Retrieving the MutliCloud Gateways")

    url = base_url + "/multicloud/devices/GCP"

    response = requests.get(url=url, headers=header,verify=False)
    if response.status_code == 200:
        items = response.json()['data']
    else:
        print("Failed to get list of multicloud gateways")
        exit()

    headers = ["Cloud Gateway Name", "Site ID", "System IP", "Reachability", "Software Version", "Status"]
    table = list()

    for item in items:
        tr = [item['cloudGatewayName'], item['site-id'], item['system-ip'], item['reachability'], item['version'], item['status']]
        table.append(tr)
    try:
        click.echo(tabulate.tabulate(table, headers, tablefmt="fancy_grid"))
    except UnicodeEncodeError:
        click.echo(tabulate.tabulate(table, headers, tablefmt="grid"))


@click.command()
def connected_sites():
    """ Retrieve connected sites.                      
        \nExample command: ./cor-multicloud.py connected-sites
    """
    click.secho("Retrieving the Connected Sites")

    url = base_url + "/multicloud/connected-sites/GCP"

    response = requests.get(url=url, headers=header,verify=False)
    if response.status_code == 200:
        items = response.json()['data']
    else:
        print("Failed to get list of connected sites")
        exit()

    headers = ["Host name", "Site ID", "Reachability", "Software Version", "BFD Sessions", "BFD Sessions Up", "Status"]
    table = list()

    for item in items:
        tr = [item['host-name'], item['site-id'], item['reachability'], item['version'], item['bfdSessions'], item['bfdSessionsUp'], item['status']]
        table.append(tr)
    try:
        click.echo(tabulate.tabulate(table, headers, tablefmt="fancy_grid"))
    except UnicodeEncodeError:
        click.echo(tabulate.tabulate(table, headers, tablefmt="grid"))





cli.add_command(associate_account)
cli.add_command(multicloud_globalsettings)
cli.add_command(discover_hostvpc)
cli.add_command(tag_hostvpc)
cli.add_command(add_cloudgateway)
cli.add_command(add_cloudconnectivity)
cli.add_command(cloud_gateway_list)
cli.add_command(connected_sites)

if __name__ == "__main__":
    cli()
