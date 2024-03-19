import json
import zipfile
import ssl
import urllib.request
import os
import zipfile
import shutil
import xml.etree.ElementTree as ET

ssl._create_default_https_context = ssl._create_unverified_context

def download_bdu_file():
    # Remove the file
    file_path = "data/vulxml.zip"
    if os.path.exists(file_path):
        os.remove(file_path)

    # Download the file from the URL
    opener = urllib.request.build_opener()
    opener.addheaders = [('User-agent', 'Mozilla/5.0')]
    urllib.request.install_opener(opener)
    urllib.request.urlretrieve(url="https://bdu.fstec.ru/files/documents/vulxml.zip",
                               filename=file_path)

def unzip_bdu_file():
    zip_file = "data/vulxml.zip"
    directory_to_extract_to = "data/vulxml"
    if os.path.exists(directory_to_extract_to):
        shutil.rmtree(directory_to_extract_to)

    with zipfile.ZipFile(zip_file, 'r') as zip_ref:
        zip_ref.extractall(directory_to_extract_to)

def parse_bdu_file():

    tree = ET.parse('data/vulxml/export/export.xml')
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
                            soft_dict["vendor"] = soft_param.text
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
                        else:
                            print("ERROR: " + soft_param.tag )
                            exit()
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
                        else:
                            print("ERROR: " + environment_param.tag )
                            exit()
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
            else:
                print("ERROR: " + vul_param.tag)
                exit()
        # print("----")

    return bdu_data


def get_bdu_data_raw(cve_id):
    f = open("data/bdu/" + cve_id + ".json", "r")
    bdu_data = json.loads(f.read())
    f.close()
    return bdu_data


def get_bdu_data(cve_id):
    bdu_data = {"raw": get_bdu_data_raw(cve_id)}
    bdu_data['description'] = ""
    bdu_data['cvss_base_score'] = ""

    return bdu_data
#
# # print(get_vulners_data(vulners_id="CVE-2021-40450", rewrite_flag=False))