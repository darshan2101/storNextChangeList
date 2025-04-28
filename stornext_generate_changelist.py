from pprint import pprint
import os
import requests
import subprocess
import json
import platform
import stat
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

global_path_list = []
global_data_map = { }
global_file_counts = { }
global_walkhrough_error = False

global_file_counts["total_size"] = 0;
global_file_counts["total_count"] = 0;
global_file_counts["delete_count"] = 0;
global_file_counts["rename_count"] = 0;
global_file_counts["bad_dir_count"] = 0;

def escape( str ):
    str = str.replace("&", "&amp;")
    str = str.replace("<", "&lt;")
    str = str.replace(">", "&gt;")
    str = str.replace("\"", "&quot;")
    return str

def get_fast_scan_work_folder():

    is_linux=0
    if platform.system() == "Linux":
        DNA_CLIENT_SERVICES = '/etc/StorageDNA/DNAClientServices.conf'
        is_linux=1
    elif platform.system() == "Darwin":
        DNA_CLIENT_SERVICES = '/Library/Preferences/com.storagedna.DNAClientServices.plist'

    fastScanWorkFolder = ""

    if is_linux == 1:
        config_parser = ConfigParser()
        config_parser.read(DNA_CLIENT_SERVICES)
        if config_parser.has_section('General') and config_parser.has_option('General','FastScanWorkFolder'):
            section_info = config_parser['General']
            fastScanWorkFolder = section_info['FastScanWorkFolder']
    else:
        with open(DNA_CLIENT_SERVICES, 'rb') as fp:
            my_plist = plistlib.load(fp)
            fastScanWorkFolder  = my_plist["FastScanWorkFolder"]

    if (len(fastScanWorkFolder) == 0):
        fastScanWorkFolder = "/tmp"
    return fastScanWorkFolder

def get_scan_folder_output_folder(project_name, project_guid):
    
    fastScanWorkFolder = get_fast_scan_work_folder()
    fastScanWorkFile = fastScanWorkFolder + '/sdna-scan-files/' + project_guid
    return fastScanWorkFile

def get_stat_file_obj(given_path, rel_path, action):

    file_map = { }

    try:
        stat_info = os.lstat(given_path)
        if stat.S_ISDIR(stat_info.st_mode):
            file_map["type"] = 'dir'
        elif stat.S_ISREG(stat_info.st_mode):
            file_map["type"] = 'file'
        else:
            return file_map

        file_map["uid"] = stat_info.st_uid
        file_map["gid"] = stat_info.st_gid
        file_map["action"] = action
        file_map["mtime"] = stat_info.st_mtime
        file_map["atime"] = stat_info.st_atime
        file_map["size"] = stat_info.st_size
        file_map["mode"] = stat_info.st_mode
        file_map["path"] = rel_path

    except (FileNotFoundError, OSError):

        file_map = {}
        file_map["type"] = 'dir'
        if os.path.isfile(given_path):
            file_map["type"] = 'file'

        epoch_time = int(time.time())

        file_map["uid"] = 0
        file_map["gid"] = 0
        file_map["action"] = action
        file_map["mtime"] = epoch_time
        file_map["atime"] = epoch_time
        file_map["size"] = 0
        file_map["mode"] = "0x777"

        if action != '-':
            file_map["type"] = 'dir'
            file_map["action"] = "BADDIR"
            global_file_counts["bad_dir_count"] = global_file_counts["bad_dir_count"] +  1
        else:
            file_map["action"] = "-"
            file_map["type"] = 'file'
            global_file_counts["delete_count"] = global_file_counts["delete_count"] +  1

        file_map["entry"] = given_path
        file_map["path"] = rel_path

    return file_map

def process_stornext_results(mapped_path, source_path, my_list, deletes_on, out_config):

    if "/./" in source_path:
        source_parts = source_path.split("/./")
        source_path = "/".join(source_parts)

    for line in my_list:
        action = '+'
        pathname = f'{mapped_path}{line}'

        try:

            if not pathname.startswith(source_path):
                continue

            elif action == 'M' or action =='+':
                rel_path = pathname[len(source_path):]
                file_map = get_stat_file_obj(pathname, rel_path, action)
                global_data_map[rel_path] = file_map
                global_path_list.append(rel_path)
            else:
                if len(action) == 0:
                    continue

                print("Unknown action found in listing: " + action)
                sys.exit(99)

            if file_map["type"] == 'file':
                global_file_counts["total_size"] = global_file_counts["total_size"] + file_map["size"]
                global_file_counts["total_count"] =  global_file_counts["total_count"] + 1

        except OSError:
            file_map = {}
            file_map["type"] = 'dir'
            if os.path.isfile(pathname):
                file_map["type"] = 'file'
            file_map["action"] = "BADDIR"
            file_map["entry"] = path
            global_file_counts["bad_dir_count"] = global_file_counts["bad_dir_count"] + 1

def write_xml_result(xml_file, index):

    total_count = global_file_counts["total_count"]
    total_size = global_file_counts["total_size"]
    delete_count = global_file_counts["delete_count"]
    bad_dir_count = global_file_counts["bad_dir_count"]

    xml_file.write("<files scanned=\"" + str(total_count) + "\" selected=\"" + str(total_count) + "\" size=\"" + str(total_size) + "\" bad_dir_count=\"" + str(bad_dir_count)+ "\" delete_count=\"" + str(delete_count) + "\">\n");

    global_path_list.sort()

    for list_entry in reversed(global_path_list):

        entry = global_data_map[list_entry]
        if entry['type'] == 'file':
             if  entry['action'] == '+' or entry['action'] == 'M':
                 xml_file.write("    <file name=\"" + escape(entry['path']) + "\" size=\"" + str(entry['size'])  + "\" mode=\"0x777\"  type=\"F_REG\" mtime=\"" + str(int(entry['mtime'])) + "\" atime=\"" + str(int(entry['atime'])) + "\" owner=\"" + str(entry['uid']) + "\" group=\"" + str(entry['gid']) + "\" index=\"" + str(index) + "\"/>\n")
             elif entry['action'] == 'R' and len(entry['rename-from']) > 0:
                 xml_file.write("    <file name=\"" + escape(entry['path']) +  "\" from=\"" + escape(entry['rename-from']) + "\" size=\"" + str(entry['size'])  + "\" mode=\"0x777\"  type=\"F_REG\" mtime=\"" + str(int(entry['mtime'])) + "\" atime=\"" + str(int(entry['atime'])) + "\" owner=\"" + str(entry['uid']) + "\" group=\"" + str(entry['gid']) + "\" index=\"" + str(index) + "\"/>\n")
             elif entry['action'] == '-':
                 xml_file.write("    <deleted-file name=\"" + escape(entry['path']) +  "\" from=\"" + escape(entry['rename-from']) + "\" size=\"" + str(entry['size'])  + "\" mode=\"0x777\"  type=\"F_REG\" mtime=\"" + str(int(entry['mtime'])) + "\" atime=\"" + str(int(entry['atime'])) + "\" owner=\"" + str(entry['uid']) + "\" group=\"" + str(entry['gid']) + "\" index=\"" + str(index) + "\"/>\n")
        elif entry['action'] == 'BADDIR':
                 xml_file.write("    <bad-dir name=\"" + escape(entry['path']) +  "\" from=\"" + escape(entry['rename-from']) + "\" size=\"" + str(entry['size'])  + "\" mode=\"0x777\"  type=\"F_REG\" mtime=\"" + str(int(entry['mtime'])) + "\" atime=\"" + str(int(entry['atime'])) + "\" owner=\"" + str(entry['uid']) + "\" group=\"" + str(entry['gid']) + "\" index=\"" + str(index) + "\"/>\n")

    xml_file.write("</files>\n")
    xml_file.close()

def find_mount_point(path):
    path = os.path.abspath(path)
    while not os.path.ismount(path):
        path = os.path.dirname(path)
    return path


if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--projectname', required = True, help = 'Project we are performing scan for.')
    parser.add_argument('-g', '--projectguid', required = True, help = 'Project guid we are performing scan for.')
    parser.add_argument('-i', '--sourceindex', required = True, help = 'Numeric index of source folders')
    parser.add_argument('-m', '--mappedpath', required = True, help = 'Path result should be mapped to.')
    parser.add_argument('-s', '--sourcepath', required = True, help = 'Source path to look for.')
    parser.add_argument('--prevsnapshotid', required = True, help = 'Required prev snapshot')
    parser.add_argument('--newsnapshotid', required = True, help = 'Required new snapshot')
    parser.add_argument('--hostname', required = True, help = 'Source hostname needed for Stornext.')
    parser.add_argument('-o', '--port', required = True, help = 'Source port (needed for Stornext.')
    parser.add_argument('-t', '--token', required = True, help = 'Source token (needed for Stornext.')
    parser.add_argument('-d', '--deletes', help = 'Use mirror deletes', action='store_true')

    args = parser.parse_args()
    output_dict = {}

    output_folder = get_scan_folder_output_folder(args.projectname, args.projectguid)
    if not os.path.isdir(output_folder):
        os.makedirs(output_folder, exist_ok=True)
    if not os.path.isdir(output_folder):
        pathlib.Path(output_folder).mkdir(parents=True, exist_ok=True)
        print("Unable to create output folder")
        exit(4)

    params = {
        'details': 'sa',
        'marker': args.prevsnapshotid,
        'end_marker': args.newsnapshotid,
        'sync': 'true',
        'exclude': '.*DS_Store'
    }

    token_decoded = args.token
    token_bytes = token_decoded.encode('ascii')
    base64_bytes = base64.b64encode(token_bytes)
    encoded_token = base64_bytes.decode('ascii')

    url = f'https://{args.hostname}:{args.port}/api/metadb/v1/change_list'
    auth_header = f'Basic {encoded_token}'
    header = {'Authorization' : auth_header}

    response = requests.get(url, headers=header,  params=params, verify=False)
    if response.status_code != 200:
        print("Error contacting Stornext: " + response.status_code)
        exit(22)

    out_config = {}

   # print(response.json())

    mapped_path = find_mount_point(args.sourcepath)
    if mapped_path == '/':
        print("Error finding mountpoint")
        exit(23)

    process_stornext_results(mapped_path, args.sourcepath, response.json()['paths'], args.deletes, out_config)

    output_file = output_folder + "/" + str(args.sourceindex) + "-files.xml"
    xml_file = open(output_file, "w")

    write_xml_result(xml_file, args.sourceindex)
    print(output_file)

    exit(0)

