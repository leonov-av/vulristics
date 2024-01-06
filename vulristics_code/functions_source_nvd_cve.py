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
    if not "CVE" in cve_id:
        nvd_cve_data['error'] = True
        nvd_cve_data['status'] = cve_id + " doesn't look like a valied CVE ID"
        nvd_cve_data['not_found_error'] = True
        return nvd_cve_data

    if credentials.nvd_key == "":
        print("Requesting " + cve_id + " from NVD website WITHOUT authorization key")
        status_not_200 = True
        while status_not_200:
            r = requests.get("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=" + cve_id)
            if r.status_code == 200:
                status_not_200 = False
            elif r.status_code == 503:
                print("Status 503 Service Unavailable. Trying again after 5 seconds sleep...")
                time.sleep(5)
                status_not_200 = True
            elif "Request forbidden by administrative rules" in r.text:
                print("Rate limit error")
                exit()
            else:
                print("Strange status:")
                print(r.status_code)
                print(r.text)
                exit()
        time.sleep(6)
    else:
        print("Requesting " + cve_id + " from NVD website WITH authorization key")
        headers = {
            'apiKey': credentials.nvd_key,
        }
        status_not_200 = True
        while status_not_200:
            r = requests.get("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=" + cve_id, headers=headers)
            if r.status_code == 200:
                status_not_200 = False
            elif r.status_code == 503:
                print("Status 503 Service Unavailable. Trying again after 5 seconds sleep...")
                time.sleep(5)
                status_not_200 = True
            elif "Request forbidden by administrative rules" in r.text:
                print("Rate limit error")
                exit()
            else:
                print("Strange status:")
                print(r.status_code)
                print(r.text)
                exit()
        time.sleep(0.6)

    try:
        nvd_cve_data = r.json()
        nvd_cve_data['error'] = False
        nvd_cve_data['status'] = "CVE ID " + cve_id + " was found on nvd.nist.gov portal"
        nvd_cve_data['not_found_error'] = False
    except:
        nvd_cve_data['error'] = True
        nvd_cve_data['status'] = "CVE ID " + cve_id + " is NOT found on nvd.nist.gov portal"
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


    if 'vulnerabilities' in nvd_cve_data['raw']:
        if len(nvd_cve_data['raw']['vulnerabilities']) > 0:
            for description in nvd_cve_data['raw']['vulnerabilities'][0]['cve']['descriptions']:
                if description['lang'] == "en":
                    nvd_cve_data['description'] = re.sub("\\n"," ",description['value'])

            short_cpes = list()
            if 'configurations' in nvd_cve_data['raw']['vulnerabilities'][0]['cve']:
                for cpe in re.findall("cpe:[^']*", str(nvd_cve_data['raw']['vulnerabilities'][0]['cve']['configurations'])):
                    if "2.3" in cpe:
                        cpe = cpe.replace("\\\\:", "<colon>")
                        short_cpe = cpe.split(":")[2] + ":" + cpe.split(":")[3] + ":" + cpe.split(":")[4]
                        if not short_cpe in short_cpes:
                            short_cpes.append(short_cpe)
            nvd_cve_data['short_cpes'] = short_cpes

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

            nvd_cve_data['cwes'] = list()
            if 'weaknesses' in nvd_cve_data['raw']['vulnerabilities'][0]['cve']:
                for weaknesses in nvd_cve_data['raw']['vulnerabilities'][0]['cve']['weaknesses']:
                    nvd_cve_data['cwes'].append(weaknesses['description'][0]['value'])


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

    return nvd_cve_data