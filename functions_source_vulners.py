import requests
import os
import json


### Data
def get_vulners_data_from_nvd_site(vulners_id):
    # https://vulners.com/docs
    # https://vulners.com/api/v3/search/id/?id=CVE-2017-7827&references=True
    # vulners_id = "CVE-2020-1003"
    vulners_data = dict()
    try:
        r = requests.get("https://vulners.com/api/v3/search/id/?id=" + vulners_id + " &references=True")
        # Without API you will be banned if you haven't solved CAPTCHA on vulners.com for 3 hours.
        # TODO processing https://github.com/vulnersCom/api
        vulners_data = r.json()
        vulners_data['error'] = False
        vulners_data['status'] = "ID was found on vulners.com portal"
        vulners_data['not_found_error'] = False
    except:
        vulners_data['error'] = True
        vulners_data['status'] = "ID is NOT found on vulners.com portal"
        vulners_data['not_found_error'] = True
    return(vulners_data)


def download_vulners_data_raw(vulners_id, rewrite_flag = True):
    file_path = "data/vulners/" + vulners_id + ".json"
    if not rewrite_flag:
        if not os.path.exists(file_path):
            # print(vulners_id)
            cve_data = get_vulners_data_from_nvd_site(vulners_id)
            f = open(file_path, "w")
            f.write(json.dumps(cve_data))
            f.close()
    else:
        # print(vulners_id)
        cve_data = get_vulners_data_from_nvd_site(vulners_id)
        f = open(file_path, "w")
        f.write(json.dumps(cve_data))
        f.close()


def get_vulners_data_raw(vulners_id):
    f = open("data/vulners/" + vulners_id + ".json", "r")
    vulners_data = json.loads(f.read())
    f.close()
    return(vulners_data)


def get_vulners_data(vulners_id, rewrite_flag):
    download_vulners_data_raw(vulners_id, rewrite_flag)
    vulners_data = get_vulners_data_raw(vulners_id)
    # if vulners_data['not_found_error'] == False:
    #     vulners_data = add_cve_product_and_type_tags(vulners_data)
    #     vulners_data = heuristic_change_product_vuln_type(vulners_data)
    #     vulners_data = add_vulners_severity(vulners_data)
    return(vulners_data)