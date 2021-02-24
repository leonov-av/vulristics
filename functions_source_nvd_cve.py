import functions_analysis_text
import requests
import os
import json

### CVE Data
def get_nvd_cve_data_from_nvd_site(cve_id):
    # https://nvd.nist.gov/General/News/New-NVD-CVE-CPE-API-and-SOAP-Retirement
    # https://csrc.nist.gov/CSRC/media/Projects/National-Vulnerability-Database/documents/web%20service%20documentation/Automation%20Support%20for%20CVE%20Retrieval.pdf
    # https://services.nvd.nist.gov/rest/json/cve/1.0/CVE-2015-5611
    # cve_id = "CVE-2020-1003"
    nvd_cve_data = dict()
    try:
        r = requests.get("https://services.nvd.nist.gov/rest/json/cve/1.0/" + cve_id)
        nvd_cve_data = r.json()
        nvd_cve_data['error'] = False
        nvd_cve_data['status'] = "CVE ID was found on nvd.nist.gov portal"
        nvd_cve_data['not_found_error'] = False
    except:
        nvd_cve_data['error'] = True
        nvd_cve_data['status'] = "CVE ID is NOT found on nvd.nist.gov portal"
        nvd_cve_data['not_found_error'] = True
    return(nvd_cve_data)


def download_nvd_cve_data_raw(cve_id, rewrite_flag = True):
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
        f.write(json.dumps(cve_data))
        f.close()


def get_nvd_cve_data_raw(cve_id):
    f = open("data/nvd_cve/" + cve_id + ".json", "r")
    nvd_cve_data = json.loads(f.read())
    f.close()
    return(nvd_cve_data)


def get_nvd_cve_data(cve_id, rewrite_flag):
    download_nvd_cve_data_raw(cve_id, rewrite_flag)
    nvd_cve_data = get_nvd_cve_data_raw(cve_id)
    # if nvd_cve_data['not_found_error'] == False:
    #     nvd_cve_data = add_cve_product_and_type_tags(nvd_cve_data)
    #     nvd_cve_data = heuristic_change_product_vuln_type(nvd_cve_data)
    #     nvd_cve_data = add_nvd_cve_severity(nvd_cve_data)
    return(nvd_cve_data)

nvd_cve_data = get_nvd_cve_data("CVE-2021-1647",False)
description = nvd_cve_data['result']['CVE_Items'][0]['cve']['description']['description_data'][0]['value']
analysed_description = functions_analysis_text.get_analysed_description(description)
print(analysed_description)
print(analysed_description['html_content'])
print(analysed_description['vulnerability_types'])
print(analysed_description['vulnerable_products'])
print(analysed_description['tags'])