import requests
import os
import json
import credentials
import functions_analysis_text
import vulners


# Search
def get_last_vulners_exploits_by_release_date():
    # https://vulners.com/search?query=published:2020-08-01%20AND%20bulletinFamily:exploit
    # https://avleonov.com/2016/04/21/vulners-com-search-api/
    try:
        print("Requesting from Vulners website WITH authorization key")
        # date = "2020-08-01"
        # r = requests.get( "https://vulners.com/api/v3/search/lucene/?query=published:" + date + "%20AND%20bulletinFamily:exploit&references=True&size=100&apiKey=" + credentials.vulners_key)
        r = requests.get(
            "https://vulners.com/api/v3/search/lucene/?query=last 5 days bulletinFamily:exploit&apiKey=" + credentials.vulners_key)
        # Without API you will be banned if you haven't solved CAPTCHA on vulners.com for 3 hours.
        vulners_exploits_data = r.json()
        print(vulners_exploits_data)
    except:
        vulners_exploits_data = dict()
    return (vulners_exploits_data)


# Data
def get_vulners_data_from_vulners_site(vulners_id):
    # https://vulners.com/docs
    # https://vulners.com/api/v3/search/id/?id=CVE-2017-7827&references=True
    # vulners_id = "CVE-2020-1003"
    vulners_data = dict()
    if credentials.vulners_key == "":
        try:
            print("Requesting " + vulners_id + " from Vulners website WITHOUT authorization key")
            r = requests.get("https://vulners.com/api/v3/search/id/?id=" + vulners_id + " &references=True")
            # Without API you will be banned if you haven't solved CAPTCHA on vulners.com for 3 hours.
            vulners_data = r.json()
            vulners_data['error'] = False
            vulners_data['status'] = "ID was found on vulners.com portal"
            vulners_data['not_found_error'] = False
        except:
            vulners_data['error'] = True
            vulners_data['status'] = "ID is NOT found on vulners.com portal"
            vulners_data['not_found_error'] = True
    else:
        # # https://github.com/vulnersCom/api
        # vulners_api = vulners.Vulners(api_key=credentials.vulners_keys)
        # vulners_data = vulners_api.document(identificator = vulners_id, references = True)
        # if vulners_data != {}:
        #     vulners_data['error'] = False
        #     vulners_data['status'] = "ID was found on vulners.com portal"
        #     vulners_data['not_found_error'] = False
        # else:
        #     vulners_data['error'] = True
        #     vulners_data['status'] = "ID is NOT found on vulners.com portal"
        #     vulners_data['not_found_error'] = True

        try:
            print("Requesting " + vulners_id + " from Vulners website WITH authorization key")
            r = requests.get(
                "https://vulners.com/api/v3/search/id/?id=" + vulners_id + " &references=True&apiKey=" + credentials.vulners_key)
            # Without API you will be banned if you haven't solved CAPTCHA on vulners.com for 3 hours.
            vulners_data = r.json()
            vulners_data['error'] = False
            vulners_data['status'] = "ID was found on vulners.com portal"
            vulners_data['not_found_error'] = False
        except:
            vulners_data['error'] = True
            vulners_data['status'] = "ID is NOT found on vulners.com portal"
            vulners_data['not_found_error'] = True
    return (vulners_data)


def download_vulners_data_raw(vulners_id, rewrite_flag=True):
    file_path = "data/vulners/" + vulners_id + ".json"
    if not rewrite_flag:
        if not os.path.exists(file_path):
            # print(vulners_id)
            cve_data = get_vulners_data_from_vulners_site(vulners_id)
            f = open(file_path, "w")
            f.write(json.dumps(cve_data, indent=4))
            f.close()
    else:
        # print(vulners_id)
        cve_data = get_vulners_data_from_vulners_site(vulners_id)
        f = open(file_path, "w")
        f.write(json.dumps(cve_data, indent=4))
        f.close()


def get_vulners_data_raw(vulners_id):
    f = open("data/vulners/" + vulners_id + ".json", "r")
    vulners_data = json.loads(f.read())
    f.close()
    return (vulners_data)


def get_vulners_data(vulners_id, rewrite_flag):
    download_vulners_data_raw(vulners_id, rewrite_flag)
    vulners_data = get_vulners_data_raw(vulners_id)
    if not vulners_data['not_found_error']:
        vulners_data['bulletins_types'] = dict()
        if 'references' in vulners_data['data']:
            for reference in vulners_data['data']['references'][vulners_id.upper()]:
                for bulletin in vulners_data['data']['references'][vulners_id.upper()][reference]:
                    if not "msf:ilities" in bulletin['id'].lower(): # Ignoring Rapid7 Metasploit IDs that are in fact vulnerabilities, not exploits
                        if bulletin['bulletinFamily'] not in vulners_data['bulletins_types']:
                            vulners_data['bulletins_types'][bulletin['bulletinFamily']] = list()
                        vulners_data['bulletins_types'][bulletin['bulletinFamily']].append(
                            {"id": bulletin['id'], "type": bulletin['type'], "title": bulletin['title'], "href": bulletin['href']})
        if 'exploit' in vulners_data['bulletins_types']:
            vulners_data['public_exploit'] = True
            vulners_data['public_exploit_sources'] = vulners_data['bulletins_types']['exploit']
        else:
            vulners_data['public_exploit'] = False
            vulners_data['public_exploit_sources'] = list()
    vulners_data['wild_exploited'] = False
    if 'data' in vulners_data:
        if 'documents' in vulners_data['data']:
            if vulners_id in vulners_data['data']['documents']:
                if 'enchantments' in vulners_data['data']['documents'][vulners_id]:
                    if 'exploitation' in vulners_data['data']['documents'][vulners_id]['enchantments']:
                        vulners_data['wild_exploited'] = \
                            vulners_data['data']['documents'][vulners_id]['enchantments']['exploitation']['wildExploited']
                        vulners_data['wild_exploited_sources'] = \
                            vulners_data['data']['documents'][vulners_id]['enchantments']['exploitation'][
                                'wildExploitedSources']

                description = vulners_data['data']['documents'][vulners_id]['description']
                cvss_base_score = ""
                if 'cvss' in  vulners_data['data']['documents'][vulners_id]:
                    cvss_base_score = vulners_data['data']['documents'][vulners_id]['cvss']['score']

                detection_results = functions_analysis_text.analyse_sentence(description)
                vulners_data['description'] = description
                vulners_data['description_tags'] = detection_results
                vulners_data['cvss_base_score'] = cvss_base_score
                vulners_data['basic_severity'] = ""
                vulners_data['vuln_product'] = detection_results['detected_product_name']
                vulners_data['vuln_type'] = detection_results['detected_vulnerability_type']

    return (vulners_data)
