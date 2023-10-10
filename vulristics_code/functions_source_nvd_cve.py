import requests
import os
import json
import time
import credentials

# CVE Data
def get_nvd_cve_data_from_nvd_site(cve_id):
    # https://nvd.nist.gov/developers/start-here#divBestPractices
    # https://services.nvd.nist.gov/rest/json/cve/1.0/CVE-2015-5611
    # cve_id = "CVE-2020-1003"
    nvd_cve_data = dict()
    if credentials.nvd_key == "":
        print("Requesting " + cve_id + " from NVD website WITHOUT authorization key")
        r = requests.get("https://services.nvd.nist.gov/rest/json/cve/1.0/" + cve_id)
        time.sleep(6)
    else:
        print("Requesting " + cve_id + " from NVD website WITH authorization key")
        headers = {
            'apiKey': credentials.nvd_key,
        }
        r = requests.get("https://services.nvd.nist.gov/rest/json/cve/1.0/" + cve_id, headers=headers)
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
    nvd_cve_data = get_nvd_cve_data_raw(cve_id)
    description = ""
    cvss_bs = ""
    if 'result' in nvd_cve_data:
        description = nvd_cve_data['result']['CVE_Items'][0]['cve']['description']['description_data'][0]['value']
        if 'impact' in nvd_cve_data['result']['CVE_Items'][0]:
            if 'baseMetricV3' in nvd_cve_data['result']['CVE_Items'][0]['impact']:
                cvss_bs = nvd_cve_data['result']['CVE_Items'][0]['impact']['baseMetricV3']['cvssV3']['baseScore']
    nvd_cve_data['description'] = description
    nvd_cve_data['cvss_base_score'] = cvss_bs
    return nvd_cve_data