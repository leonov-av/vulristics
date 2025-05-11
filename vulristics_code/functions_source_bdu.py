import json
import zipfile
import ssl
import urllib.request
import os
import zipfile
import shutil
import xml.etree.ElementTree as ET
import sys
import re

ssl._create_default_https_context = ssl._create_unverified_context

def download_bdu_file():
    # Remove the file
    file_path = "data/bdu/vulxml/vulxml.zip"
    if os.path.exists(file_path):
        os.remove(file_path)

    # Download the file from the URL
    opener = urllib.request.build_opener()
    opener.addheaders = [('User-agent', 'Mozilla/5.0')]
    urllib.request.install_opener(opener)
    urllib.request.urlretrieve(url="https://bdu.fstec.ru/files/documents/vulxml.zip",
                               filename=file_path)

def unzip_bdu_file():
    zip_file = "data/bdu/vulxml/vulxml.zip"
    directory_to_extract_to = "data/bdu/vulxml/bdu_extracted/"
    if os.path.exists(directory_to_extract_to):
        shutil.rmtree(directory_to_extract_to)

    with zipfile.ZipFile(zip_file, 'r') as zip_ref:
        zip_ref.extractall(directory_to_extract_to)

def parse_bdu_file():
    tree = ET.parse('data/bdu/vulxml/bdu_extracted/export/export.xml')
    root = tree.getroot()

    bdu_data = dict()

    for vul in root:
        for vul_param in vul:
            if vul_param.tag == "identifier":
                vul_id = vul_param.text
                bdu_data[vul_id] = dict()
        for vul_param in vul:
            if vul_param.tag == "description":
                bdu_data[vul_id]["description"] = vul_param.text
            elif vul_param.tag == "name":
                bdu_data[vul_id]["name"] = vul_param.text
            elif vul_param.tag == "identifier":
                bdu_data[vul_id]["identifier"] = vul_param.text
            elif vul_param.tag == "vul_class":
                bdu_data[vul_id]["vul_class"] = vul_param.text
            elif vul_param.tag == "solution":
                bdu_data[vul_id]["solution"] = vul_param.text
            elif vul_param.tag == "severity":
                bdu_data[vul_id]["severity"] = vul_param.text
            elif vul_param.tag == "vul_status":
                bdu_data[vul_id]["vul_status"] = vul_param.text
            elif vul_param.tag == "vul_incident":
                bdu_data[vul_id]["vul_incident"] = vul_param.text
            elif vul_param.tag == "fix_status":
                bdu_data[vul_id]["fix_status"] = vul_param.text
            elif vul_param.tag == "exploit_status":
                bdu_data[vul_id]["exploit_status"] = vul_param.text
            elif vul_param.tag == "identify_date":
                bdu_data[vul_id]["identify_date"] = vul_param.text
            elif vul_param.tag == "other":
                bdu_data[vul_id]["other"] = vul_param.text
            elif vul_param.tag == "sources":
                bdu_data[vul_id]["sources"] = vul_param.text
            elif vul_param.tag == "identifiers":
                bdu_data[vul_id]["identifiers"] = list()
                for ident in vul_param:
                    bdu_data[vul_id]["identifiers"].append({
                        "type": ident.attrib['type'],
                        "value": ident.text
                    })
            elif vul_param.tag == "vulnerable_software":
                bdu_data[vul_id]["soft"] = list()
                for soft in vul_param:
                    soft_dict = {}
                    for soft_param in soft:
                        if soft_param.tag == "vendor":
                            soft_dict["vendor"] = soft_param.text
                        elif soft_param.tag == "name":
                            soft_dict["name"] = soft_param.text
                        elif soft_param.tag == "platform":
                            soft_dict["platform"] = soft_param.text
                        elif soft_param.tag == "version":
                            soft_dict["version"] = soft_param.text
                        elif soft_param.tag == "registry_number":
                            soft_dict["registry_number"] = soft_param.text
                        elif soft_param.tag == "types":
                            soft_dict["types"] = list()
                            for software_type in soft_param:
                                soft_dict["types"].append(software_type.text)
                        # else:
                        #     print("ERROR: " + soft_param.tag )
                        #     exit()
                    bdu_data[vul_id]["soft"].append(soft_dict)
            elif vul_param.tag == "environment":
                bdu_data[vul_id]["environment"] = list()
                for environment in vul_param:
                    environment_dict = {}
                    for environment_param in environment:
                        environment_dict["type"] = environment_param.tag
                        if environment_param.tag == "vendor":
                            environment_dict["vendor"] = soft_param.text
                        elif environment_param.tag == "name":
                            environment_dict["name"] = soft_param.text
                        elif environment_param.tag == "version":
                            environment_dict["version"] = soft_param.text
                        elif environment_param.tag == "platform":
                            environment_dict["platform"] = soft_param.text
                        elif environment_param.tag == "registry_number":
                            environment_dict["registry_number"] = soft_param.text
                        # else:
                        #     print("ERROR: " + environment_param.tag )
                        #     exit()
                    bdu_data[vul_id]["environment"].append(environment_dict)
            elif vul_param.tag == "cvss":
                for cvss_param in vul_param:
                    if cvss_param.tag == "vector":
                        bdu_data[vul_id]["cvss"] = {'vector': cvss_param.text,
                                                    'score': cvss_param.attrib['score']}
            elif vul_param.tag == "cvss3":
                for cvss_param in vul_param:
                    if cvss_param.tag == "vector":
                        bdu_data[vul_id]["cvss3"] = {'vector': cvss_param.text,
                                                    'score': cvss_param.attrib['score']}

            elif vul_param.tag == "cwe":
                bdu_data[vul_id]["cwe"] = list()
                for cwe_identifier in vul_param:
                    bdu_data[vul_id]["cwe"].append(cwe_identifier.text)
            # else:
            #     print("ERROR: " + vul_param.tag)
            #     exit()
        # print("----")

    for bdu_id in bdu_data:
        bdu_entity = bdu_data[bdu_id]
        bdu_data[bdu_id]['processed'] = {}
        cve_ids = list()
        if 'identifiers' in bdu_entity:
            for identifier in bdu_entity['identifiers']:
                if identifier['type'] == 'CVE':
                    cve_ids.append(identifier['value'])
        bdu_data[bdu_id]['processed']['cve_ids'] = cve_ids
    return bdu_data

def make_bdu_vuln_files():
    bdu_data = parse_bdu_file()
    for item_id in bdu_data:
        f = open("data/bdu/" + item_id + ".json", "w")
        # print(bdu_data[item_id])
        f.write(json.dumps(bdu_data[item_id], indent=4))
        f.close()
        for cve_id in bdu_data[item_id]['processed']['cve_ids']:
            bdu_data[item_id]['processed']['from_bdu'] = item_id
            cve_id = re.sub('\u2011', "-", cve_id)
            cve_id = re.sub('\u2013', "-", cve_id)
            cve_id = re.sub('\u200b', "-", cve_id)
            f = open("data/bdu/" + cve_id + ".json", "w")
            f.write(json.dumps(bdu_data[item_id], indent=4))
            f.close()

def get_bdu_data_raw(cve_id):

    if os.path.isfile("data/bdu/" + cve_id + ".json"):
        f = open("data/bdu/" + cve_id + ".json", "r")
        bdu_data = json.loads(f.read())
        f.close()
    else:
        bdu_data = {}
    return bdu_data


def get_bdu_data(cve_id, source_config):
    raw_data = get_bdu_data_raw(cve_id)
    bdu_data = {"raw": raw_data}


    if raw_data != {}:
        bdu_data['description'] = ""
        if 'cvss' in bdu_data["raw"]:
            bdu_data['cvss_base_score'] = bdu_data["raw"]['cvss']['score']
        if 'cvss3' in bdu_data["raw"]:
            bdu_data['cvss_base_score'] = bdu_data["raw"]['cvss3']['score']

        if source_config['bdu_use_vulnerability_descriptions_flag']:
            bdu_data['description'] = bdu_data["raw"]['description']

        if 'cwe' in bdu_data["raw"]:
            bdu_data['cwes'] = bdu_data["raw"]['cwe']

        if  bdu_data["raw"]['vul_incident'] == "1":
            bdu_data['wild_exploited'] = True
            bdu_data['wild_exploited_sources'] = [
                {
                  "type": "bdu",
                  "text": "BDU",
                  "url": "https://bdu.fstec.ru/vul/" + bdu_data["raw"]['identifier'].split(":")[1]
                }
            ]

        if bdu_data["raw"]['exploit_status'] == "Существует":
            bdu_data['private_exploit'] = True
            bdu_data['private_exploit_sources'] = [
                {
                  "type": "bdu",
                  "text": "BDU:PrivateExploit",
                  "url": "https://bdu.fstec.ru/vul/" + bdu_data["raw"]['identifier'].split(":")[1]
                }
            ]

        if bdu_data["raw"]['exploit_status'] == "Существует в открытом доступе":
            bdu_data['public_exploit'] = True
            bdu_data['public_exploit_sources'] = [
                {
                  "type": "bdu",
                  "text": "BDU:PublicExploit",
                  "url": "https://bdu.fstec.ru/vul/" + bdu_data["raw"]['identifier'].split(":")[1]
                }
            ]

        if source_config['bdu_use_product_names_flag']:
            if bdu_data["raw"]['soft'] != []:
                bdu_data['product_name'] = bdu_data["raw"]['soft'][0]['name']

    return bdu_data

# # print(get_vulners_data(vulners_id="CVE-2021-40450", rewrite_flag=False))