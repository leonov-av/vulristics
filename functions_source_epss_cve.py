import requests
import os
import json


# CVE Data
def get_epss_cve_data_from_epss_site(cve_id):
    # https://www.first.org/epss/api
    # https://api.first.org/data/v1/epss?cve=CVE-2022-27225
    # cve_id = "CVE-2020-1003"
    epss_cve_data = dict()
    try:
        print("Requesting " + cve_id + " from epss website")
        r = requests.get("https://api.first.org/data/v1/epss?cve=" + cve_id)
        epss_cve_data = r.json()
        epss_cve_data['error'] = False
        epss_cve_data['status'] = "CVE ID was found on api.first.org portal"
        epss_cve_data['not_found_error'] = False
    except:
        epss_cve_data['error'] = True
        epss_cve_data['status'] = "CVE ID is NOT found on api.first.org portal"
        epss_cve_data['not_found_error'] = True
    return epss_cve_data


def download_epss_cve_data_raw(cve_id, rewrite_flag=True):
    file_path = "data/epss_cve/" + cve_id + ".json"
    if not rewrite_flag:
        if not os.path.exists(file_path):
            # print(cve_id)
            cve_data = get_epss_cve_data_from_epss_site(cve_id)
            f = open(file_path, "w")
            f.write(json.dumps(cve_data))
            f.close()
    else:
        # print(cve_id)
        cve_data = get_epss_cve_data_from_epss_site(cve_id)
        f = open(file_path, "w")
        f.write(json.dumps(cve_data, indent=4))
        f.close()


def get_epss_cve_data_raw(cve_id):
    f = open("data/epss_cve/" + cve_id + ".json", "r")
    epss_cve_data = json.loads(f.read())
    f.close()
    return epss_cve_data


def get_epss_cve_data(cve_id, rewrite_flag):
    download_epss_cve_data_raw(cve_id, rewrite_flag)
    epss_cve_data = get_epss_cve_data_raw(cve_id)
    epss = 0
    epss_percentile = 0

    #{"status":"OK","status-code":200,"version":"1.0","access":"public",
    # "total":1,"offset":0,"limit":100,"data":[{"cve":"CVE-2022-27225",
    # "epss":"0.001320000","percentile":"0.467510000","date":"2023-04-09"}]}

    if 'data' in epss_cve_data:
        if 'data' in epss_cve_data:
            if len(epss_cve_data['data']) != 0:
                epss = float(epss_cve_data['data'][0]['epss'])
                epss_percentile = float(epss_cve_data['data'][0]['percentile'])
    epss_cve_data['epss'] = epss
    epss_cve_data['epss_percentile'] = epss_percentile
    return epss_cve_data