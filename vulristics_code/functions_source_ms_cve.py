import json
import re
import os
import requests


def get_ms_cve_search_data(from_date, to_date, skip):
    headers = {
        'authority': 'api.msrc.microsoft.com',
        'sec-ch-ua': '"Google Chrome";v="89", "Chromium";v="89", ";Not A Brand";v="99"',
        'accept': 'application/json, text/plain, */*',
        'sec-ch-ua-mobile': '?0',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)' +
                      ' Chrome/89.0.4389.90 Safari/537.36',
        'origin': 'https://msrc.microsoft.com',
        'sec-fetch-site': 'same-site',
        'sec-fetch-mode': 'cors',
        'sec-fetch-dest': 'empty',
        'referer': 'https://msrc.microsoft.com/',
        'accept-language': 'en-US,en;q=0.9,ru;q=0.8',
    }
    params = (
        ('$orderby', 'releaseDate desc'),
        ('$filter', '(releaseDate gt ' + from_date + 'T00:00:00+03:00) and (releaseDate lt ' +
         to_date + 'T23:59:59+03:00)'),
        ('$skip', str(skip)),
    )
    response = requests.get('https://api.msrc.microsoft.com/sug/v2.0/en-US/vulnerability', headers=headers,
                            params=params)
    return response.json()


def get_ms_vulns_for_date_range(from_date, to_date):
    # Interface for service https://msrc.microsoft.com/update-guide/en-us
    # from_date = "2021-03-09"
    # to_date = "2021-03-09"
    all_cves = list()
    other_vulns = list()
    continue_processing = True
    skip = 0
    while continue_processing:
        data = get_ms_cve_search_data(from_date, to_date, skip)
        if len(data['value']) != 0:
            for value in data['value']:
                if "CVE" in value['cveNumber']:
                    all_cves.append(value['cveNumber'])
                else:
                    other_vulns.append(value['cveNumber'])
        else:
            continue_processing = False
        skip += 500

    return set(all_cves), set(other_vulns)


def get_ms_cve_data_from_ms_site(cve_id):
    # CVE Data
    # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-1003
    # cve_id = "CVE-2020-1003"
    ms_cve_data = dict()
    try:
        print("Requesting " + cve_id + " from Microsoft website")
        # HTML page https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2020-1003
        # 1) Main information: https://api.msrc.microsoft.com/sug/v2.0/en-US/vulnerability/CVE-2020-1003
        # cveTitle, description
        # Flags:
        # "publiclyDisclosed": "No",
        # "exploited": "No",
        # "latestSoftwareRelease": "Exploitation Less Likely",
        # "olderSoftwareRelease": "Exploitation Less Likely",
        # "denialOfService": "N/A"
        # 2) CVSS and vulnerable products  https://api.msrc.microsoft.com
        #                           /sug/v2.0/en-US/affectedProduct?%24filter=cveNumber+eq+%27CVE-2020-1003%27
        ms_cve_data = dict()
        ms_cve_data['main'] = requests.get("https://api.msrc.microsoft.com/sug/v2.0/en-US/vulnerability/" +
                                           cve_id).json()
        ms_cve_data['vuln_products'] = requests.get("https://api.msrc.microsoft.com/sug/v2.0/en-US/"
                                                    "affectedProduct?%24filter=cveNumber+eq+%27" +
                                                    cve_id + "%27").json()
        ms_cve_data['error'] = False
        ms_cve_data['status'] = "CVE ID was found on microsoft.com portal"
        ms_cve_data['not_found_error'] = False
    except:
        ms_cve_data['main'] = dict()
        ms_cve_data['vuln_products'] = dict()
        ms_cve_data['error'] = True
        ms_cve_data['status'] = "CVE ID is NOT found on microsoft.com portal"
        ms_cve_data['not_found_error'] = True
    return ms_cve_data


def download_ms_cve_data_raw(cve_id, rewrite_flag=True):
    file_path = "data/ms_cve/" + cve_id + ".json"
    if not rewrite_flag:
        if not os.path.exists(file_path):
            # print(cve_id)
            cve_data = get_ms_cve_data_from_ms_site(cve_id)
            f = open(file_path, "w")
            f.write(json.dumps(cve_data, indent=4))
            f.close()
    else:
        # print(cve_id)
        cve_data = get_ms_cve_data_from_ms_site(cve_id)
        f = open(file_path, "w")
        f.write(json.dumps(cve_data, indent=4))
        f.close()


def get_ms_cve_data_raw(cve_id):
    f = open("data/ms_cve/" + cve_id + ".json", "r")
    ms_cve_data = json.loads(f.read())
    f.close()
    return ms_cve_data


def add_ms_cve_severity(ms_cve_data):
    severities = set()
    severity_numbers = set()
    severity_numbers.add(0)
    severity_dict = {"critical": 4, "important": 3, "moderate": 2, "low": 1, "n/a": 0}
    result_severity = ""

    for block in ms_cve_data['vuln_products']['value']:
        if 'severity' in block:
            severities.add(block['severity'].lower())
    for severity in severities:
        for severity_val in severity_dict:
            if severity == severity_val:
                severity_numbers.add(severity_dict[severity_val])
    max_severity_number = max(severity_numbers)
    for severity_val in severity_dict:
        if severity_dict[severity_val] == max_severity_number:
            result_severity = severity_val
    ms_cve_data['severity'] = result_severity
    return ms_cve_data


def add_ms_cve_cvss_base_score(ms_cve_data):
    all_base_score = list()
    all_exploit = list()
    cvss_base_score = ""
    exploit_value = 0
    if 'value' in ms_cve_data['vuln_products']:
        for data in ms_cve_data['vuln_products']['value']:
            if 'baseScore' in data:
                all_base_score.append(data['baseScore'])
                if "E:" in data['vectorString']:
                    exploit_value_product = re.findall("E:([^/]*)",data['vectorString'])[0]
                    if exploit_value_product == "P":
                        exploit_value_product = 1
                    elif exploit_value_product == "F":
                        exploit_value_product = 2
                    elif exploit_value_product == "H":
                        exploit_value_product = 3
                    else:
                        exploit_value_product = 0
                    all_exploit.append(exploit_value_product)

    if all_base_score != list():
        cvss_base_score = max(all_base_score)
    if all_exploit != list():
        exploit_value = max(all_exploit)

    exploit_value_name = ""
    exploit_value_name_c = 0
    if exploit_value == 1:
        exploit_value_name = "Proof-of-Concept Exploit"
        exploit_value_name_c = 0.4
    elif exploit_value == 2:
        exploit_value_name = "Functional Exploit"
        exploit_value_name_c = 0.6
    elif exploit_value == 3:
        exploit_value_name = "Autonomous Exploit"
        exploit_value_name_c = 0.8
    
    if exploit_value != 0:
        ms_cve_data['public_exploit'] = True
    else:
        ms_cve_data['public_exploit'] = False
    ms_cve_data['public_exploit_level_name'] = exploit_value_name
    ms_cve_data['public_exploit_level'] = exploit_value_name_c

    ms_cve_data['cvss_base_score'] = cvss_base_score
    return ms_cve_data

def get_ms_cve_data(cve_id, source_config):
    rewrite_flag = source_config['rewrite_flag']
    download_ms_cve_data_raw(cve_id, rewrite_flag)
    ms_cve_data = get_ms_cve_data_raw(cve_id)
    if not ms_cve_data['not_found_error']:
        ms_cve_data['description'] = ""
        if 'description' in ms_cve_data['main']:
            ms_cve_data['description'] = re.sub("<[^>]*>","",ms_cve_data['main']['description'])
        ms_cve_data['title'] = ms_cve_data['main']['cveTitle']
        if 'exploited' in ms_cve_data['main']:
            ms_cve_data['exploited'] = ms_cve_data['main']['exploited']
        else:
            ms_cve_data['exploited'] = "No"
        ms_cve_data = add_ms_cve_severity(ms_cve_data)
        ms_cve_data = add_ms_cve_cvss_base_score(ms_cve_data)
    return ms_cve_data


# def debug_get_ms_cve_data():
#     ms_cve_data = get_ms_cve_data(cve_id="CVE-2022-22006", rewrite_flag=True)
#     print(json.dumps(ms_cve_data, indent=4))
# 
# debug_get_ms_cve_data()