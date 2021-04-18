import requests
import re
import os
import json

### CVE Data
def get_direct_links_for_cve(cve_id):
    # cve_id = 'CVE-2020-16952'
    headers = {
        'authority': 'attackerkb.com',
        'upgrade-insecure-requests': '1',
        'user-agent': 'Mozilla/5.0 (iPad; CPU OS 11_0 like Mac OS X) AppleWebKit/604.1.34 (KHTML, like Gecko) Version/11.0 Mobile/15A5341f Safari/604.1',
        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
        'sec-fetch-site': 'none',
        'sec-fetch-mode': 'navigate',
        'sec-fetch-user': '?1',
        'sec-fetch-dest': 'document',
        'accept-language': 'en-US,en;q=0.9,ru;q=0.8'
    }

    r = requests.get("https://attackerkb.com/search?q=" + cve_id, headers=headers)
    urls = re.findall("(/topics/[^/]*/[^\"\?]*)", r.text)
    urls = set(urls)
    urls_with_cve_id = set()
    for url in urls:
        if cve_id.lower() in url:
            urls_with_cve_id.add("https://attackerkb.com" + url)
    return(urls_with_cve_id)


def get_attackerkb_data_by_derect_url(url):
    # url = 'https://attackerkb.com/topics/4yGC4tLK2x/cve-2020-16952-microsoft-sharepoint-remote-code-execution-vulnerabilities'
    # url = 'https://attackerkb.com/topics/oOQnGlyZAN/cve-2020-10148-solarwinds-orion-api-authentication-bypass-and-rce?referrer=moreFromAKB'
    headers = {
        'authority': 'attackerkb.com',
        'upgrade-insecure-requests': '1',
        'user-agent': 'Mozilla/5.0 (iPad; CPU OS 11_0 like Mac OS X) AppleWebKit/604.1.34 (KHTML, like Gecko) Version/11.0 Mobile/15A5341f Safari/604.1',
        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
        'sec-fetch-site': 'none',
        'sec-fetch-mode': 'navigate',
        'sec-fetch-user': '?1',
        'sec-fetch-dest': 'document',
        'accept-language': 'en-US,en;q=0.9,ru;q=0.8'
    }

    data = dict()
    r = requests.get(url, headers=headers)
    if "<span>Exploited in the Wild</span>" in r.text:
        data['Exploited in the Wild'] = True
    else:
        data['Exploited in the Wild'] = False
    tags_raw = re.findall('<span class="[a-z]*-tag [a-z]*">[^<]*</span>',r.text)
    data['tags'] = dict()
    for tag in tags_raw:
        text = re.sub("<[^>]*>","",tag)
        level = re.findall("-tag ([^\"]*)", tag)[0]
        data['tags'][text] = {'level':level}
    return(data)


def get_attackerkb_cve_data_from_attackerkb_site(cve_id):
    # cve_id = "CVE-2020-1003"
    attackerkb_cve_data = dict()
    try:
        print("Requesting " + cve_id + " from AttackerKB website WITHOUT authorization key")
        urls_with_cve_id = get_direct_links_for_cve(cve_id)
        results = dict()
        results['Exploited in the Wild'] = False
        results['tags'] = dict()
        results['urls'] = list(urls_with_cve_id)
        for url in urls_with_cve_id:
            data = get_attackerkb_data_by_derect_url(url)
            if data['Exploited in the Wild'] == True:
                results['Exploited in the Wild'] = True
            for tag in data['tags']:
                results['tags'][tag] = data['tags'][tag]
        attackerkb_cve_data = results
        attackerkb_cve_data['error'] = False
        attackerkb_cve_data['status'] = "CVE ID was found on attackerkb.com portal"
        attackerkb_cve_data['not_found_error'] = False
    except:
        attackerkb_cve_data['error'] = True
        attackerkb_cve_data['status'] = "CVE ID is NOT found on attackerkb.com portal"
        attackerkb_cve_data['not_found_error'] = True
    return(attackerkb_cve_data)


def download_attackerkb_cve_data_raw(cve_id, rewrite_flag = True):
    file_path = "data/attackerkb_cve/" + cve_id + ".json"
    if not rewrite_flag:
        if not os.path.exists(file_path):
            # print(cve_id)
            cve_data = get_attackerkb_cve_data_from_attackerkb_site(cve_id)
            f = open(file_path, "w")
            f.write(json.dumps(cve_data))
            f.close()
    else:
        # print(cve_id)
        cve_data = get_attackerkb_cve_data_from_attackerkb_site(cve_id)
        f = open(file_path, "w")
        f.write(json.dumps(cve_data))
        f.close()


def get_attackerkb_cve_data_raw(cve_id):
    f = open("data/attackerkb_cve/" + cve_id + ".json", "r")
    try:
        attackerkb_cve_data = json.loads(f.read())
    except:
        print("Error in get_attackerkb_cve_data_raw(cve_id) for " + str(cve_id))
        print("File: " + "data/attackerkb_cve/" + str(cve_id) + ".json")
        exit()
    f.close()
    return(attackerkb_cve_data)


def get_attackerkb_cve_data(cve_id, rewrite_flag):
    download_attackerkb_cve_data_raw(cve_id, rewrite_flag)
    attackerkb_cve_data = get_attackerkb_cve_data_raw(cve_id)
    return(attackerkb_cve_data)

def check_attackerkb_cve():
    path = "data/attackerkb_cve"
    files = [f for f in os.listdir(path) if os.path.isfile(os.path.join(path, f))]
    for file in files:
        if ".json" in file:
            f = open(path + "/" + file, "r")
            try:
                object = json.loads(f.read())
                if object['urls'] == list():
                    print("Empty urls: " + file)
            except:
                print("Not JSON: " + file)
                exit()
            f.close()