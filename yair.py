#!/usr/bin/env python3

"""
Gathers Vulnerability Information and outputs it in a fancy way :-)
"""
import os
import sys
import json
import requests
from tabulate import tabulate
import textwrap
import yaml
import argparse

arg_parser = argparse.ArgumentParser()

arg_parser.add_argument("--config", action="store", dest="config_file", default="/opt/yair/config/config.yaml",
    help="Config file location. Defaults to /opt/yair/config/config.yaml")

arg_parser.add_argument("--no-namespace", action="store_true", dest="no_namespace", default=False,
    help="If your image names doesnt contain the \"namespace\" and its not in the default \"library\" namespace.")

arg_parser.add_argument("--registry", action="store",
    help="Overwrites the \"registry::host\" configfile option.")

arg_parser.add_argument("image", action="store",
    help="The image you want to scan. if you provide no tag we will assume \"latest\". if you provide no namespace we will assume \"library\".")

args = arg_parser.parse_args()

try:
    with open(args.config_file, 'r') as cfg:
        config = yaml.load(cfg)
except yaml.parser.ParserError:
    print("error while parsing config.yaml", file=sys.stderr)
    exit(1)
except FileNotFoundError:
    print("config file \"" + args.config_file + "\" not found - exiting")
    exit(1)

sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', 100)
sys.stderr = os.fdopen(sys.stderr.fileno(), 'w', 100)

image_score_fail_on=config['fail_on']['score']
big_vuln_fail_on=bool(config['fail_on']['big_vulnerability'])
docker_registry=config['registry']['host']
output=config['output']['format']
clair_server=config['clair']['host']

try:
    rocket_chat_enable=True
    rocket_hook_url = config['output']['rocketchat']['webhook_url']
    rocket_receiver= config['output']['rocketchat']['receiver'].split(",")
except KeyError:
    rocket_chat_enable=False

if args.registry != None:
    docker_registry = args.registry

image = args.image
try:
    image, image_tag = image.rsplit(':', 1)
except ValueError:
    image_tag = "latest"

image_s = image.split('/')
if len(image_s) == 1:
    if args.no_namespace == True:
        image_name = image
    else:
        image_name = "library/" + image
elif len(image_s) >= 2:
    image_name = image

def y_req(address, method, h=None, data=None):
    if h is None:
        h = {}

    if data is None:
        data = {}

    try:
        if method == "get":
            req_result = requests.get(address, headers=h)
            req_result.raise_for_status()
        elif method == "post":
            req_result = requests.post(address, headers=h, data=data)
            req_result.raise_for_status()
        elif method == "delete":
            req_result = requests.delete(address, headers=h)
            req_result.raise_for_status()
        return req_result
    except requests.exceptions.HTTPError as err:
        print(err, file=sys.stderr)
        exit(1)
    except requests.exceptions.ConnectionError as err:
        print("connection to {} failed".format(address), file=sys.stderr)
        exit(1)


def get_image_manifest():
    global registry_token
    req_headers = {}
    req_url = "https://" + docker_registry + "/v2/" + image_name + "/manifests/" + image_tag
    req_headers['Accept'] = 'application/vnd.docker.distribution.manifest.v2+json'
    try:
        req_result = requests.get(req_url, headers=req_headers)
        if req_result.status_code == 401:
            auth_header = req_result.headers['WWW-Authenticate'].split(',')
            registry_auth = auth_header[0].replace('Bearer realm=', '').replace('"', '')
            registry_service = auth_header[1].replace('"', '')
            registry_scope = auth_header[2].replace('"', '')
            req_url = registry_auth + "?" + registry_service + "&" + registry_scope + "&offline_token"
            req_result = y_req(req_url, "get")
            data = json.loads(req_result.text)
            registry_token = "Bearer " + data['token']
            req_headers['Authorization'] = registry_token
        else:
            registry_token = ""
            req_result.raise_for_status()
    except requests.exceptions.HTTPError as err:
        print(err, file=sys.stderr)
        exit(1)
    except requests.exceptions.ConnectionError as err:
        print("connection to {} failed".format(req_url), file=sys.stderr)

        exit(1)

    req_url = "https://" + docker_registry + "/v2/" + image_name + "/manifests/" + image_tag
    req_headers['Accept'] = 'application/vnd.docker.distribution.manifest.v2+json'
    req_result = y_req(req_url, "get", h=req_headers)
    if req_result.status_code == 404:
        raise ValueError("image not found")
    req_result.raise_for_status()


    data = json.loads(req_result.text)
    return data

def get_image_layers():
    manifest = get_image_manifest()
    if manifest['schemaVersion'] == 1:
        result = list(map(lambda x: x['blobSum'], manifest['fsLayers']))
        result.reverse() # schema v1 need the reversed order
        # result.remove('a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4') # layer needs to be filtered
        return result

    elif manifest['schemaVersion'] == 2:
        result = list(map(lambda x: x['digest'], manifest['layers']))
        return result

    else:
        raise NotImplementedError("unknown schema version")

def analyse_image():
    # delete old check results
    try:
        req_url = "http://" + clair_server + "/v1/layers/" + layers[-1]
        req_result = requests.delete(req_url)
        if req_result.status_code != 404:
            req_result.raise_for_status()
    except requests.exceptions.HTTPError as err:
        print(err, file=sys.stderr)
        exit(1)
    except requests.exceptions.ConnectionError as err:
        print("connection to {} failed".format(req_url), file=sys.stderr)
        exit(1)


    for i in range(0, len(layers)):
        json_data = { "Layer": { "Name": "", "Path": "", "Headers": { "Authorization": "" }, "ParentName": "", "Format": "" }} # json template
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

        y_req(req_url, "post", data=json.dumps(json_data), h=req_headers)

def get_image_info():
    vuln_data = []
    severitys= ["Unknown","Negligible","Low", "Medium", "High", "Critical", "Defcon1"]

    req_url = "http://" + clair_server + "/v1/layers/" + layers[-1] + "?features&vulnerabilities"
    req_headers = {'Content-Type': 'application/json'}
    req_result = y_req(req_url, "get", h=req_headers)

    data = req_result.json()
    if 'Features' not in data['Layer']:
        print("could not find any package in the given image", file=sys.stderr)
        exit(0)
    data = data['Layer']['Features']
    for d in data:
        if "Vulnerabilities" in d:
            for v in d['Vulnerabilities']:
                vd = dict (
                    package_name = d['Name'],
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

                for i in range(0, len(severitys)):
                    if severitys[i] == vd['cve_severity']:
                        vd['cve_severity_nr'] = i

    return vuln_data

def send_to_rocket(message, emoji):
    if rocket_chat_enable:
        for receiver in rocket_receiver:
            payload = {"icon_emoji": emoji, "channel": receiver, "text": message}
            y_req(rocket_hook_url, "post", data=json.dumps(payload))

def output_data():
    image_score = 0
    big_vuln = False
    table = []
    vuln_data.sort(key=lambda vuln: vuln['cve_severity_nr'], reverse=True)


    for vuln in vuln_data:
        if vuln['cve_severity_nr'] >= 4:
            big_vuln = True
        if vuln['cve_fixed_version'] != "":
            image_score += vuln['cve_severity_nr']**4

    if output == "table":
        headers = ["Package\nInstalled Version", "CVE Name\nSeverity", "CVE Link\nCVE Description", "Version with fix"]
        for vuln in vuln_data:
            vuln['cve_desc'] = vuln['cve_link'] + "\n\n" +  textwrap.fill(vuln['cve_desc'], 64)
            vuln['package'] = vuln['package_name'] + "\n\n" + vuln['installed_version']
            vuln['cve'] = vuln['cve_name'] + "\n\n" + vuln['cve_severity']
            table.append([vuln['package'], vuln['cve'], vuln['cve_desc'], vuln['cve_fixed_version']])

        print(tabulate(table, headers=headers, tablefmt="grid"),
              file=sys.stdout)

    elif output == "short-table":
        headers = ["Package", "CVE Name", "Severity", "Version with fix"]
        for vuln in vuln_data:
            table.append([vuln['package_name'], vuln['cve_name'], vuln['cve_severity'], vuln['cve_fixed_version']])

        print(tabulate(table, headers=headers, tablefmt="psql"),
              file=sys.stdout)

    elif output == "json":
        print(json.dumps(vuln_data), file=sys.stdout)

    elif output == "quiet":
        if big_vuln and big_vuln_fail_on:
            exit(2)
        elif image_score < image_score_fail_on:
            exit(0)
        else:
            exit(2)


    print("scan result for: {}:{}".format(image_name, image_tag),
          file=sys.stderr)

    if big_vuln and big_vuln_fail_on:
        send_to_rocket('The security scan for "{}:{}" has found an '
                       'vulnerability with severity high or higher!'
                       .format(image_name, image_tag),
                       ":information_source:")
        print("the image has \"high\" vulnerabilities", file=sys.stderr)
        exit(2)
    elif image_score < image_score_fail_on:
        exit(0)
    else:
        send_to_rocket('The security scan for "{}:{}" has found an '
                       'vulnerability score of {}!'
                       .format(image_name, image_tag, image_score),
                       ":information_source:")
        print("the image has to many fixable vulnerabilities", file=sys.stderr)
        exit(2)


if __name__ == '__main__':
    layers = get_image_layers()
    analyse_image()
    vuln_data = get_image_info()
    output_data()


