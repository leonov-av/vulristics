import requests
import os
import json
import time
import credentials
import re

# CVE Data
def get_nvd_cve_data_from_nvd_site(cve_id):
    # https://nvd.nist.gov/developers/start-here#divBestPractices
    # https://services.nvd.nist.gov/rest/json/cve/1.0/CVE-2015-5611
    # cve_id = "CVE-2020-1003"
    nvd_cve_data = dict()
    if credentials.nvd_key == "":
        print("Requesting " + cve_id + " from NVD website WITHOUT authorization key")
        r = requests.get("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=" + cve_id)
        time.sleep(6)
    else:
        print("Requesting " + cve_id + " from NVD website WITH authorization key")
        headers = {
            'apiKey': credentials.nvd_key,
        }
        r = requests.get("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=" + cve_id, headers=headers)
        time.sleep(0.6)
    if "Request forbidden by administrative rules" in r.text:
        print("Rate limit error")
        exit()
    try:
        nvd_cve_data = r.json()
        nvd_cve_data['error'] = False
        nvd_cve_data['status'] = "CVE ID was found on nvd.nist.gov portal"
        nvd_cve_data['not_found_error'] = False
    except:
        nvd_cve_data['error'] = True
        nvd_cve_data['status'] = "CVE ID is NOT found on nvd.nist.gov portal"
        nvd_cve_data['not_found_error'] = True
    return nvd_cve_data


def download_nvd_cve_data_raw(cve_id, rewrite_flag=True):
    file_path = "data/nvd_cve/" + cve_id + ".json"
    if not rewrite_flag:
        if not os.path.exists(file_path):
            # print(cve_id)
            cve_data = get_nvd_cve_data_from_nvd_site(cve_id)
            f = open(file_path, "w")
            f.write(json.dumps(cve_data))
            f.close()
    else:
        # print(cve_id)
        cve_data = get_nvd_cve_data_from_nvd_site(cve_id)
        f = open(file_path, "w")
        f.write(json.dumps(cve_data, indent=4))
        f.close()


def get_nvd_cve_data_raw(cve_id):
    f = open("data/nvd_cve/" + cve_id + ".json", "r")
    nvd_cve_data = json.loads(f.read())
    f.close()
    return nvd_cve_data


def get_nvd_cve_data(cve_id, source_config):
    rewrite_flag = source_config['rewrite_flag']
    download_nvd_cve_data_raw(cve_id, rewrite_flag)
    nvd_cve_data = {"raw": get_nvd_cve_data_raw(cve_id)}
    nvd_cve_data['description'] = ""
    nvd_cve_data['cvss_base_score'] = ""

    if len(nvd_cve_data['raw']['vulnerabilities']) > 0:
        for description in nvd_cve_data['raw']['vulnerabilities'][0]['cve']['descriptions']:
            if description['lang'] == "en":
                nvd_cve_data['description'] = re.sub("\\n","",description['value'])

        cvss_priorities = ["cvssMetricV2", "cvssMetricV30", "cvssMetricV31"]
        for cvss_type in cvss_priorities:
            for metric_type in nvd_cve_data['raw']['vulnerabilities'][0]['cve']['metrics']:
                if metric_type == cvss_type:
                    for metric_value in nvd_cve_data['raw']['vulnerabilities'][0]['cve']['metrics'][metric_type]:
                        nvd_cve_data['cvss_base_score'] = metric_value['cvssData']['baseScore']
        if "cisaExploitAdd" in nvd_cve_data['raw']['vulnerabilities'][0]['cve']:
            cve_id = nvd_cve_data['raw']['vulnerabilities'][0]['cve']['id']
            url = 'https://nvd.nist.gov/vuln/detail/' + cve_id
            nvd_cve_data['wild_exploited'] = True
            nvd_cve_data['wild_exploited_sources'] = list()
            nvd_cve_data['wild_exploited_sources'].append({'type': 'nvd_cisa_kev',
                                                           'text': "NVD:CISAKEV",
                                                           'url': url})

        for reference in nvd_cve_data['raw']['vulnerabilities'][0]['cve']['references']:
            if 'tags' in reference:
                if 'Exploit' in reference['tags']:
                    url = reference['url']
                    text = "NVD:Exploit:" + re.sub("/.*","", re.sub("^https*://","", url))
                    nvd_cve_data['public_exploit'] = True
                    nvd_cve_data['public_exploit_sources'] = list()
                    nvd_cve_data['public_exploit_sources'].append({'type': 'nvd_exploit_type_link',
                                                                   'text': text,
                                                                   'url': url})
    return nvd_cve_data;