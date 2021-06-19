import json
import re
import os
import requests
import data_classification_vulnerability_types
import functions_tools


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
    response = requests.get('https://api.msrc.microsoft.com/sug/v2.0/en-US/affectedProduct', headers=headers,
                            params=params)
    return response.json()


def get_ms_cves_for_date_range(from_date, to_date):
    # Interface for service https://msrc.microsoft.com/update-guide/en-us
    # from_date = "2021-03-09"
    # to_date = "2021-03-09"
    all_cves = list()
    continue_processing = True
    skip = 0
    while continue_processing:
        data = get_ms_cve_search_data(from_date, to_date, skip)
        if len(data['value']) != 0:
            for value in data['value']:
                all_cves.append(value['cveNumber'])
        else:
            continue_processing = False
        skip += 500
    return set(all_cves)


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
        ms_cve_data['main'] = requests.get("https://api.msrc.microsoft.com/sug/v2.0/en-US/vulnerability/" + cve_id).json()
        ms_cve_data['vuln_products'] = requests.get("https://api.msrc.microsoft.com/sug/v2.0/en-US/"
                                                    "affectedProduct?%24filter=cveNumber+eq+%27" + cve_id + "%27").json()
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


def get_vuln_product_and_type_from_title(title):
    vuln_type = ""
    vuln_product = ""
    for pattern in data_classification_vulnerability_types.vulnerability_type_detection_patterns:
        if pattern in title:
            vuln_type = data_classification_vulnerability_types.vulnerability_type_detection_patterns[pattern]
            vuln_product = re.sub("[ \t]*" + pattern + ".*$", "", title)
    return vuln_type, vuln_product


def add_cve_product_and_type_tags(ms_cve_data):
    ms_cve_data['vuln_type'], ms_cve_data['vuln_product'] = get_vuln_product_and_type_from_title(
        ms_cve_data['main']['cveTitle'])
    if ms_cve_data['main']['cveTitle'] != "RETRACTED":
        if 'vuln_type' not in ms_cve_data:
            functions_tools.print_debug_message("No vuln_type in ms_cve_data for " + ms_cve_data['cveNumber'])
            functions_tools.print_debug_message(json.dumps(ms_cve_data, indent=4))
            exit()
        if 'vuln_product' not in ms_cve_data:
            functions_tools.print_debug_message("No vuln_product in ms_cve_data for " + ms_cve_data['cveNumber'])
            functions_tools.print_debug_message(json.dumps(ms_cve_data, indent=4))
            exit()
    return ms_cve_data


def add_ms_cve_severity(ms_cve_data):
    severities = set()
    severity_numbers = set()
    severity_numbers.add(0)
    severity_dict = {"critical": 4, "important": 3, "moderate": 2, "low": 1, "n/a": 0}
    result_severity = ""

    for block in ms_cve_data['vuln_products']['value']:
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
    cvss_base_score = ""
    if 'value' in ms_cve_data['vuln_products']:
        for data in ms_cve_data['vuln_products']['value']:
            all_base_score.append(data['baseScore'])
    if all_base_score != list():
        cvss_base_score = max(all_base_score)
    ms_cve_data['cvss_base_score'] = cvss_base_score
    return ms_cve_data


# Heuristics
def heuristic_change_product_vuln_type(ms_cve_data):
    if 'vuln_product' in ms_cve_data:
        ms_cve_data['vuln_product'] = re.sub("Microsoft Windows","Windows", ms_cve_data['vuln_product'])

        if re.findall("Azure .*",  ms_cve_data['vuln_product']):
            ms_cve_data['vuln_product'] = "Azure"
        if re.findall("Visual Studio .*",  ms_cve_data['vuln_product']):
            ms_cve_data['vuln_product'] = "Visual Studio"

        if ms_cve_data['vuln_product'] == "Windows SMB":
            ms_cve_data['vuln_product'] = "SMB"
        if ms_cve_data['vuln_product'] == "Windows NTFS":
            ms_cve_data['vuln_product'] = "NTFS"

        if ms_cve_data['vuln_product'] == "Windows TCP/IP Driver":
            ms_cve_data['vuln_product'] = "Windows TCP/IP"
        if ms_cve_data['vuln_product'] == "Microsoft Outlook":
            ms_cve_data['vuln_product'] = "Outlook"
        if ms_cve_data['vuln_product'] == "Diagnostics Hub Standard Collector Service":
            ms_cve_data['vuln_product'] = "Diagnostics Hub Standard Collector"
        if ms_cve_data['vuln_product'] == "Windows DNS":
            ms_cve_data['vuln_product'] = "Windows DNS Server"
        if ms_cve_data['vuln_product'] == "Microsoft Office SharePoint":
            ms_cve_data['vuln_product'] = "Microsoft SharePoint"
        if ms_cve_data['vuln_product'] == "ASP.NET Core and Visual Studio":
            ms_cve_data['vuln_product'] = "ASP.NET Core"
        if ms_cve_data['vuln_product'] == "Microsoft splwow64":
            ms_cve_data['vuln_product'] = "splwow64"
        if ms_cve_data['vuln_product'] == "Microsoft SharePoint Server":
            ms_cve_data['vuln_product'] = "Microsoft SharePoint"
        if ms_cve_data['vuln_product'] == "Windows VBScript Engine":
            ms_cve_data['vuln_product'] = "VBScript"
        if ms_cve_data['vuln_product'] == "Windows Defender Antimalware Platform Hard Link":
            ms_cve_data['vuln_product'] = "Microsoft Defender"
        if ms_cve_data['vuln_product'] == "Win32k":
            ms_cve_data['vuln_product'] = "Windows Kernel"
        if ms_cve_data['vuln_product'] == "SharePoint":
            ms_cve_data['vuln_product'] = "Microsoft SharePoint"
        if ms_cve_data['vuln_product'] == "Scripting Engine" and \
                "Internet Explorer" in ms_cve_data['description']:
            ms_cve_data['vuln_product'] = "Internet Explorer"
        if ms_cve_data['vuln_product'] == "Scripting Engine" and \
                "ChakraCore scripting engine" in ms_cve_data['description']:
            ms_cve_data['vuln_product'] = "Chakra Scripting Engine"
    if 'vuln_product' in ms_cve_data:
        if ms_cve_data['vuln_type'] == "Memory Corruption" and \
                re.findall("[Rr]emote code execution", ms_cve_data['description']):
            ms_cve_data['vuln_type'] = "Remote Code Execution"
    return ms_cve_data


def get_ms_cve_data(cve_id, rewrite_flag):
    download_ms_cve_data_raw(cve_id, rewrite_flag)
    ms_cve_data = get_ms_cve_data_raw(cve_id)
    if not ms_cve_data['not_found_error']:
        ms_cve_data = add_cve_product_and_type_tags(ms_cve_data)
        ms_cve_data['description'] =  ms_cve_data['main']['description']
        ms_cve_data['exploited'] = ms_cve_data['main']['exploited']
        ms_cve_data = heuristic_change_product_vuln_type(ms_cve_data)
        ms_cve_data = add_ms_cve_severity(ms_cve_data)
        ms_cve_data = add_ms_cve_cvss_base_score(ms_cve_data)
    return ms_cve_data


# def debug_get_ms_cve_data():
#     ms_cve_data = get_ms_cve_data(cve_id="CVE-2021-31955", rewrite_flag=True)
#     print(json.dumps(ms_cve_data, indent=4))