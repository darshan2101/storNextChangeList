from pprint import pprint
import os
import requests
import subprocess
import json
import platform
import time
import sys
import time    
import argparse
from configparser import ConfigParser
import plistlib
import ssl
import base64
import urllib3

urllib3.disable_warnings()


if __name__ == '__main__':

    params = {
        'details': 'sa',
        'marker': '4062',
        'sync': 'true',
        'end_marker': '5064',
        'exclude': '.*DS_Store'
    }

    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--projectname', required = True, help = 'Project we are performing scan for.')
    parser.add_argument('-s', '--sourcepath', required = True, help = 'Source path (needed for Stornext.')
    parser.add_argument('--hostname', required = True, help = 'Source hostname needed for Stornext.')
    parser.add_argument('-o', '--port', required = True, help = 'Source port (needed for Stornext.')
    parser.add_argument('-t', '--token', required = True, help = 'Source token (needed for Stornext.')
    args = parser.parse_args()

    output_dict = {}

    token_decoded = args.token
    token_bytes = token_decoded.encode('ascii')
    base64_bytes = base64.b64encode(token_bytes)
    encoded_token = base64_bytes.decode('ascii')

    url = f'https://{args.hostname}:{args.port}/api/metadb/v1/marker'
    auth_header = f'Basic {encoded_token}'
    header = {'Authorization' : auth_header}

    response = requests.get(url, headers=header,  params=params, verify=False)
    if response.status_code != 200:
        print("Error contacting Stornext: " + str(response.status_code))
        exit(22)

    new_snapshot_id = response.json()['marker']
    print(new_snapshot_id)
    exit(0)

