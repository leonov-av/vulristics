import requests
import os
import json
import credentials
import vulners
import re

reuse_vulners_processed = False

# Search
def get_last_vulners_exploits_by_release_date():
    # https://vulners.com/search?query=published:2020-08-01%20AND%20bulletinFamily:exploit
    # https://avleonov.com/2016/04/21/vulners-com-search-api/
    try:
        print("Requesting from Vulners website WITH authorization key")
        # date = "2020-08-01"
        # r = requests.get( "https://vulners.com/api/v3/search/lucene/?query=published:" + date + "%20AND%20bulletinFamily:exploit&references=True&size=100&apiKey=" + credentials.vulners_key)
        r = requests.get(
            "https://vulners.com/api/v3/search/lucene/?query=last 5 days (!type:githubexploit AND bulletinFamily:exploit)&apiKey=" + credentials.vulners_key)
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


def collect_vulners_data(vulners_id, rewrite_flag):
    download_vulners_data_raw(vulners_id, rewrite_flag)
    vulners_data = get_vulners_data_raw(vulners_id)
    if not vulners_data['not_found_error']:
        vulners_data['bulletins_types'] = dict()
        if 'references' in vulners_data['data']:
            if vulners_id.upper() in vulners_data['data']['references']:
                for reference in vulners_data['data']['references'][vulners_id.upper()]:
                    for bulletin in vulners_data['data']['references'][vulners_id.upper()][reference]:
                        if not "msf:ilities" in bulletin['id'].lower(): # Ignoring Rapid7 Metasploit IDs that are in fact vulnerabilities, not exploits
                            if bulletin['bulletinFamily'] not in vulners_data['bulletins_types']:
                                vulners_data['bulletins_types'][bulletin['bulletinFamily']] = list()
                            vulners_data['bulletins_types'][bulletin['bulletinFamily']].append(
                                {"id": bulletin['id'], "type": bulletin['type'], "title": bulletin['title'], "href": bulletin['href']})
        if 'exploit' in vulners_data['bulletins_types']:
            vulners_data['public_exploit'] = True
            vulners_data['public_exploit_sources'] = list()
            for exploit in vulners_data['bulletins_types']['exploit']:
                if exploit['type'] == "githubexploit":
                    part_github = re.sub("https://github.com/","",exploit['href']).upper()
                    part_github = re.sub("/",":",part_github)
                    text = "Vulners:PublicExploit:GitHub:" + part_github
                    vulners_data['public_exploit'] = True
                    vulners_data['public_exploit_sources'].append({'type': 'vulners_exploit_type_link',
                                                                   'subtype': exploit['type'],
                                                                   'vulners_id': exploit['id'],
                                                                   'text': text,
                                                                   'url':exploit['href']})
                else:
                    text = "Vulners:PublicExploit:" + exploit['id']
                    vulners_data['public_exploit'] = True
                    vulners_data['public_exploit_sources'].append({'type': 'vulners_exploit_type_link',
                                                                   'subtype': exploit['type'],
                                                                   'vulners_id': exploit['id'],
                                                                   'text': text,
                                                                   'url':exploit['href']})
        else:
            vulners_data['public_exploit'] = False
            vulners_data['public_exploit_sources'] = list()
    vulners_data['wild_exploited'] = False
    bul_dict = dict()
    if "bulletins_types" in vulners_data:
        for bul_type in vulners_data['bulletins_types']:
            for bul in vulners_data['bulletins_types'][bul_type]:
                bul_dict[bul['id']] = bul
    if 'data' in vulners_data:
        if 'documents' in vulners_data['data']:
            if vulners_id in vulners_data['data']['documents']:
                if 'enchantments' in vulners_data['data']['documents'][vulners_id]:
                    if 'exploitation' in vulners_data['data']['documents'][vulners_id]['enchantments']:
                        wild_exploited = False
                        wild_exploited_sources = list()
                        if vulners_data['data']['documents'][vulners_id]['enchantments']['exploitation']:
                            if 'wildExploited' in vulners_data['data']['documents'][vulners_id]['enchantments']['exploitation']:
                                wild_exploited = vulners_data['data']['documents'][vulners_id]['enchantments']['exploitation']['wildExploited']
                            if 'wildExploitedSources' in vulners_data['data']['documents'][vulners_id]['enchantments']['exploitation']:
                                wild_exploited_sources = vulners_data['data']['documents'][vulners_id]['enchantments']['exploitation']['wildExploitedSources']

                        new_wild_exploited_sources = list()
                        if wild_exploited: # Additional check
                            for wild_exploited_source in wild_exploited_sources:
                                # print(wild_exploited_source)
                                if wild_exploited_source['type'] == "attackerkb": #Filtering only this type
                                    new_id_list = list()
                                    for attackerkb_id in wild_exploited_source['idList']:
                                        # print(attackerkb_id)
                                        if attackerkb_id in bul_dict:
                                            if 'title' in bul_dict[attackerkb_id]:
                                                if vulners_id in bul_dict[attackerkb_id]['title']:
                                                    new_id_list.append(attackerkb_id)
                                    if new_id_list != list():
                                        new_wild_exploited_sources.append({'type': 'attackerkb', 'idList': new_id_list})
                                else:
                                    new_wild_exploited_sources.append(wild_exploited_source)
                            if new_wild_exploited_sources == list():
                                wild_exploited = False
                            wild_exploited_sources = new_wild_exploited_sources

                        vulners_data['wild_exploited'] = wild_exploited
                        vulners_data['wild_exploited_sources'] = wild_exploited_sources

                description = vulners_data['data']['documents'][vulners_id]['description']
                cvss_base_score = ""
                if 'cvss' in  vulners_data['data']['documents'][vulners_id]:
                    if 'score' in vulners_data['data']['documents'][vulners_id]['cvss']:
                        cvss_base_score = vulners_data['data']['documents'][vulners_id]['cvss']['score']
                if 'cvss2' in  vulners_data['data']['documents'][vulners_id]:
                    if 'cvssV2' in vulners_data['data']['documents'][vulners_id]['cvss2']:
                        if 'baseScore' in vulners_data['data']['documents'][vulners_id]['cvss2']['cvssV2']:
                            cvss_base_score = vulners_data['data']['documents'][vulners_id]['cvss2']['cvssV2']['baseScore']
                if 'cvss3' in  vulners_data['data']['documents'][vulners_id]:
                    if 'cvssV3' in vulners_data['data']['documents'][vulners_id]['cvss3']:
                        if 'baseScore' in vulners_data['data']['documents'][vulners_id]['cvss3']['cvssV3']:
                            cvss_base_score = vulners_data['data']['documents'][vulners_id]['cvss3']['cvssV3']['baseScore']

                vulners_data['description'] = description
                vulners_data['cvss_base_score'] = cvss_base_score

    file_path_processed = "data/vulners_processed/" + vulners_id + ".json"
    f = open(file_path_processed, "w")
    f.write(json.dumps(vulners_data))
    f.close()
    return vulners_data

def get_vulners_data(vulners_id, source_config):
    file_path_processed = "data/vulners_processed/" + vulners_id + ".json"
    rewrite_flag = source_config['rewrite_flag']

    if rewrite_flag or not os.path.exists(file_path_processed) or not reuse_vulners_processed:
        vulners_data = collect_vulners_data(vulners_id, rewrite_flag)
    else:
        f = open(file_path_processed, "r")
        vulners_data = json.loads(f.read())
        f.close()

    vulners_use_github_exploits = source_config['vulners_use_github_exploits_flag']
    if vulners_use_github_exploits == False:
        new_public_exploit_sources = list()
        for source in vulners_data['public_exploit_sources']:
            if source['subtype'] != 'githubexploit':
                new_public_exploit_sources.append(source)
        if new_public_exploit_sources == list():
            vulners_data['public_exploit'] = False
        vulners_data['public_exploit_sources'] = new_public_exploit_sources


    return vulners_data

# print(get_vulners_data(vulners_id="CVE-2021-40450", rewrite_flag=False))