#!/usr/bin/env python2

"""
Gathers Vulnerability Information and outputs it in a fancy way :-)
"""

import socket
import re
import sys
import json
import requests
from tabulate import tabulate
import textwrap
from optparse import OptionParser

usage = "usage: %prog [options] image:tag"
parser = OptionParser(usage=usage)
parser.add_option("-r", "--registry", dest="registry", default="registry.hub.docker.com", help="docker registry URL without http/https prefix")
parser.add_option("-c", "--clair", dest="clair", default="localhost:6060", help="clair URL with port")
parser.add_option("-o", "--output", dest="output", default="table", help="output format \"json\" or \"table\" or \"quiet\"")
parser.add_option("-q", "--quiet", dest="output", action="store_const",const="quiet", help="quiet mode - only exitcode and stderr (-o quiet does the same)")
(options, args) = parser.parse_args()

if len(args) != 1:
    parser.error("specify an image to scan")

output=options.output
docker_registry=options.registry
clair_server=options.clair
try:
    image_name, image_tag =  args[0].split(':')
except ValueError:
    image_name = args[0]
    image_tag = "latest"

if "/" not in image_name:
    image_name = "library/" + image_name


def check_server(address):
    address = "http://" + address
    try:
        requests.get(address)
    except requests.HTTPError:
        print("Connection to " + address + " failed")


def get_image_manifest():
    global registry_token
    req_headers = {}
    req_url = "https://" + docker_registry + "/v2/" + image_name + "/manifests/" + image_tag
    req_headers['Accept'] = 'application/vnd.docker.distribution.manifest.v2+json'
    req_result = requests.get(req_url, headers=req_headers)
    if req_result.status_code == 401:
        auth_header = req_result.headers['WWW-Authenticate'].split(',')
        registry_auth = auth_header[0].replace('Bearer realm=', '').replace('"', '')
        registry_service = auth_header[1].replace('"', '')
        registry_scope = auth_header[2].replace('"', '')
        req_url = registry_auth + "?" + registry_service + "&" + registry_scope + "&offline_token"
        req_result = requests.get(req_url)
        data = json.loads(req_result.text)
        registry_token = "Bearer " + data['token']
        req_headers['Authorization'] = registry_token

    else:
        registry_token = ""

    req_url = "https://" + docker_registry + "/v2/" + image_name + "/manifests/" + image_tag
    req_headers['Accept'] = 'application/vnd.docker.distribution.manifest.v2+json'
    req_result = requests.get(req_url, headers=req_headers)
    if req_result.status_code == 404:
        raise ValueError("image not found")
    req_result.raise_for_status()


    data = json.loads(req_result.text)
    return data

def get_image_layers():
    manifest = get_image_manifest()
    if manifest['schemaVersion'] == 1:
        result = map(lambda x: x['blobSum'], manifest['fsLayers'])
        result.reverse() # schema v1 need the reversed order
        # result.remove('a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4') # layer needs to be filtered
        return result

    elif manifest['schemaVersion'] == 2:
        result = map(lambda x: x['digest'], manifest['layers'])
        return result

    else:
        raise NotImplementedError("unknown schema version")

def analyse_image():

    # delete old check results
    # print("deleting old scan results")
    req_url = "http://" + clair_server + "/v1/layers/" + layers[-1]
    requests.delete(req_url)


    for i in range(0, layers.__len__()):
        json_data = { "Layer": { "Name": "", "Path": "", "Headers": { "Authorization": "" }, "ParentName": "", "Format": "" }} # json template
        # print("uploading layer: " + layers[i])
        json_data['Layer']['Name'] = layers[i]
        json_data['Layer']['Path'] = "https://" + docker_registry + "/v2/" + image_name + "/blobs/" + layers[i]
        json_data['Layer']['Headers']['Authorization'] = registry_token
        if i == 0:
            json_data['Layer']['ParentName'] = ""
        else:
            json_data['Layer']['ParentName'] = layers[i-1]
        json_data['Layer']['Format'] = "Docker"

        req_url = "http://" + clair_server + "/v1/layers"
        req_headers = { 'Content-Type': 'application/json' }

        status = requests.post(req_url, json = json_data, headers = req_headers)
        status.raise_for_status()


def get_image_info():
    vuln_data = []
    #severitys = ["Defcon1", "Critical", "High", "Medium", "Low", "Negligible", "Unknown"]
    severitys= ["Unknown","Negligible","Low", "Medium", "High", "Critical", "Defcon1"]

    req_url = "http://" + clair_server + "/v1/layers/" + layers[-1] + "?features&vulnerabilities"
    req_headers = {'Content-Type': 'application/json'}
    req_result = requests.get(req_url, headers=req_headers)
    req_result.raise_for_status()

    data = req_result.json()
    if 'Features' not in data['Layer']:
        print("could not find any package in the given image")
        exit(0)
    data = data['Layer']['Features']
    for d in data:
        if "Vulnerabilities" in d:
            for v in d['Vulnerabilities']:
                vd = dict (
                    tool_name = d['Name'],
                    installed_version = d['Version'],

                    namespace_name = v['NamespaceName'],
                    cve_severity = v['Severity'],
                    cve_name = v['Name'],
                    cve_link = v['Link'],
                )
                if 'FixedBy' in v:
                    vd['cve_fixed_version'] = v['FixedBy']
                else:
                    vd['cve_fixed_version'] = ""
                if 'Description' in v:
                    vd['cve_desc'] = v['Description']
                else:
                    vd['cve_desc'] = ""
                vuln_data.append(vd)

                for i in range(0, severitys.__len__()):
                    if severitys[i] == vd['cve_severity']:
                        vd['cve_severity_nr'] = i



    return vuln_data

def output_data():
    global image_score
    image_score = 0
    big_vuln = False
    table = []
    headers = ["Tool", "Severity", "CVE name", "Installed Version", "Description", "Version with fix"]
    vuln_data.sort(key=lambda vuln: vuln['cve_severity_nr'], reverse=True)


    for vuln in vuln_data:
        if vuln['cve_severity_nr'] >= 4:
            big_vuln = True
        if vuln['cve_fixed_version'] != "":
            image_score += vuln['cve_severity_nr']**4



    if output == "table":
        for vuln in vuln_data:
            vuln['cve_desc'] = vuln['cve_link'] + "\n\n" +  textwrap.fill(vuln['cve_desc'], 64)
            table.append([vuln['tool_name'], vuln['cve_severity'], vuln['cve_name'], vuln['installed_version'], vuln['cve_desc'], vuln['cve_fixed_version']])
        print(tabulate(table, headers=headers, tablefmt="fancy_grid"))
        print("\nthe image \"" + image_name + ":" + image_tag + "\" has an vulnerability score of " + str(image_score))

    elif output == "json":
        print(json.dumps(vuln_data))

    if big_vuln:
        raise ValueError("the image has \"high\" vulnerabilities")
    elif image_score < 379:
        exit(0)
    else:
        raise ValueError("the image has to many fixable vulnerabilities")


if __name__ == '__main__':
    check_server(docker_registry)
    check_server(clair_server)
    layers = get_image_layers()
    analyse_image()
    vuln_data = get_image_info()
    output_data()


