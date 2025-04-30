import requests
import argparse
import base64
import urllib3
import json

urllib3.disable_warnings()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--projectname', required=True)
    parser.add_argument('-s', '--sourcepath', required=True)
    parser.add_argument('--hostname', required=True)
    parser.add_argument('-o', '--port', required=True)
    parser.add_argument('-t', '--token', required=True)
    args = parser.parse_args()

    params = {
        'details': 'sa',
        'marker': '4062',
        'sync': 'true',
        'end_marker': '5064',
        'exclude': '.*DS_Store'
    }

    token_bytes = args.token.encode('ascii')
    encoded_token = base64.b64encode(token_bytes).decode('ascii')

    url = f'https://{args.hostname}:{args.port}/api/metadb/v1/marker'
    headers = {'Authorization': f'Basic {encoded_token}'}

    try:
        response = requests.get(url, headers=headers, params=params, verify=False)
        if response.status_code != 200:
            print(json.dumps({"error": f"Stornext marker request failed with status code {response.status_code}"}))
            exit(22)

        data = response.json()
        print(json.dumps({"marker": data.get("marker")}))
        exit(0)
    except Exception as e:
        print(json.dumps({"error": str(e)}))
        exit(1)
