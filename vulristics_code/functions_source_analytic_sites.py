import requests
import trafilatura
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)
import re
from vulristics_code import functions_tools



#### Common
def get_text_from_url(url):
    response = requests.get(url)
    text = response.text
    if text:
        text = trafilatura.extract(text)
    return text


#### Qualys
def get_qualys_link(query):
    # coveo API
    headers = {
        'Connection': 'keep-alive',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'Accept': '*/*',
        'Origin': 'https://community.qualys.com',
        'Sec-Fetch-Site': 'cross-site',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Dest': 'empty',
        'Referer': 'https://community.qualys.com/',
        'Accept-Language': 'en-US,en;q=0.9,ru;q=0.8',
    }

    html_with_coveo_key = requests.get("https://community.qualys.com/search/#q=Patch&t=Blog&sort=relevancy",
                                       headers=headers).text
    if re.findall('''"coveo":{"public":{"api":{"key":"([^"]*)"}}}''', html_with_coveo_key):
        coveo_key = re.findall('''"coveo":{"public":{"api":{"key":"([^"]*)"}}}''', html_with_coveo_key)[0]

        headers = {
            'Connection': 'keep-alive',
            'Authorization': 'Bearer ' + coveo_key,
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'Accept': '*/*',
            'Origin': 'https://community.qualys.com',
            'Sec-Fetch-Site': 'cross-site',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Dest': 'empty',
            'Referer': 'https://community.qualys.com/',
            'Accept-Language': 'en-US,en;q=0.9,ru;q=0.8',
        }

        params = (
            ('searchHub', 'CommunitySearch'),
        )

        data = {
            'q': query,
            'cq': '@source=(Blog,Notifications)',
            'searchHub': 'CommunitySearch',
            'tab': 'Blog',
            'locale': 'en',
            'firstResult': '0',
            'numberOfResults': '10',
            'excerptLength': '200',
            'filterField': '@foldingcollection',
            'filterFieldRange': '2',
            'enableDidYouMean': 'true',
            'sortCriteria': 'relevancy'
        }

        response = requests.post('https://platform.cloud.coveo.com/rest/search/v2', headers=headers, params=params,
                                 data=data)
        for result in response.json()['results']:
            # print(result['title'])
            result_status = True
            for keyword in query.split(" "):
                if not keyword in result['title']:
                    result_status = False
            if result_status:
                return ({'title': result['title'], 'url': result['uri']})
    else:
        result_status = False

def get_qualys_text_from_url(url):
    headers = {
        'Connection': 'keep-alive',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'Accept': '*/*',
        'Origin': 'https://community.qualys.com',
        'Sec-Fetch-Site': 'cross-site',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Dest': 'empty',
        'Referer': 'https://community.qualys.com/',
        'Accept-Language': 'en-US,en;q=0.9,ru;q=0.8',
    }
    response = requests.get(url, headers=headers)
    qualys_html = response.text
    qualys_html = re.sub("<h","###DELIM###<h",qualys_html)
    qualys_html = re.sub("\n"," ",qualys_html)
    qualys_html = re.sub("  *"," ",qualys_html)
    qualys_html = re.sub("<[^>]*>", "", qualys_html)
    return qualys_html


def process_qualys_text(qualys_text):
    qualys_text_new = list()
    for line in qualys_text.split("###DELIM###"):
        if "CVE" in line:
            qualys_text_new.append(line)
    qualys_text_new = "\n".join(qualys_text_new)
    return qualys_text_new


#### Tenable
def get_tenable_link(query):
    headers = {
        'Connection': 'keep-alive',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'Accept': '*/*',
        'Origin': 'https://community.qualys.com',
        'Sec-Fetch-Site': 'cross-site',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Dest': 'empty',
        'Referer': 'https://community.qualys.com/',
        'Accept-Language': 'en-US,en;q=0.9,ru;q=0.8',
    }
    url = "https://www.tenable.com/blog/search?field_blog_section_tid=All&combine=" + query
    response = functions_tools.make_request(type="get", url=url, headers=headers)

    a_tags = re.findall(' <h2><a href="/blog/.*?</a>', response.text)
    for a_tag in a_tags:
        # print(a_tag)
        url = "https://www.tenable.com" + a_tag.split('"')[1]
        title = re.sub("<[^>]*>", "", a_tag)

        result_status = True
        for keyword in query.split(" "):
            if not keyword in title:
                result_status = False

        if result_status:
            return {'title': title, 'url': url}


def get_tenable_text_from_url(url):
    headers = {
        'Connection': 'keep-alive',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'Accept': '*/*',
        'Sec-Fetch-Site': 'cross-site',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Dest': 'empty',
        'Accept-Language': 'en-US,en;q=0.9,ru;q=0.8',
    }
    response = functions_tools.make_request(type="get", url=url, headers=headers)
    text = response.text
    if text:
        text = trafilatura.extract(text)
    return text


### Rapid7
def get_rapid7_link(query):
    headers = {
        'Connection': 'keep-alive',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'Accept': '*/*',
        'Sec-Fetch-Site': 'cross-site',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Dest': 'empty',
        'Accept-Language': 'en-US,en;q=0.9,ru;q=0.8',
    }

    js_with_key = requests.get("https://blog.rapid7.com/assets/js/all.js", headers=headers).text
    # print(js_with_key)
    ghost_content_api_key = \
    re.findall('''GhostContentAPI\\({url:"https://blog.rapid7.com",key:"([^"]*)",version:"[^"]*"}\\)''', js_with_key)[0]

    response = requests.get(
        "https://blog.rapid7.com/ghost/api/v3/content/posts/?key=" + ghost_content_api_key + "&limit=all&fields=url%2Ctitle",
        headers=headers)
    for post in response.json()['posts']:
        result_status = True
        for keyword in query.split(" "):
            if not keyword in post['title']:
                result_status = False
        if result_status:
            return {'title': post['title'], 'url': post['url']}


def get_rapid7_text_from_url(url):
    headers = {
        'Connection': 'keep-alive',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'Accept': '*/*',
        'Sec-Fetch-Site': 'cross-site',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Dest': 'empty',
        'Accept-Language': 'en-US,en;q=0.9,ru;q=0.8',
    }
    text = requests.get(url, headers=headers).text
    if text:
        text = trafilatura.extract(text)

    new_text = ""
    for line in text.split("\n"):
        skip = False
        if re.findall("^\\|", line):  # remove tables
            skip = True
        if re.findall("^- ", line):
            line = re.sub("^- ", "", line)
        if not skip:
            if not re.findall("\\.$", line) and "CVE-" in line:  # looks like a header; don't add new line
                new_text += line + ". "
            else:
                new_text += re.sub("\\.$", ". ", line) + "\n"  # normal line

    return (new_text)


### DuckDuckGo
def get_duckduckgo_search_results(query):
    headers = {
        'Connection': 'keep-alive',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'Accept': '*/*',
        'Sec-Fetch-Site': 'cross-site',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Dest': 'empty',
        'Accept-Language': 'en-US,en;q=0.9,ru;q=0.8',
    }
    url = "https://duckduckgo.com/html/?q=" + query
    result_text = requests.get(url, headers=headers).text
    a_tags = re.findall('''<a class="result__snippet" href.*?</a>''', result_text)
    for a_tag in a_tags:
        a_tag = re.sub('">.*',"",a_tag)
        if len(a_tag.split('"')) >= 3:
            url = a_tag.split('"')[3]
            title = re.sub("<[^>]*>", "", a_tag)
            result_status = True
            for keyword in query.split(" "):
                if not "site:" in keyword:  # ignoring ""site:https://www.zerodayinitiative.com/blog" part
                    if not keyword.lower() in title.lower():
                        # print("Error: '" + keyword.lower() + "' is not in '" + title.lower() + "'")
                        result_status = False
            if result_status:
                return {'title': title, 'url': url}
    return None


def get_duckduckgo_search_results_multiple_queries(queries):
    for query in queries:
        print(query)
        result = get_duckduckgo_search_results(query)
        if result is not None:
            return result
    return None


### ZDI

def get_zdi_search_results(query):
    headers = {
        'Connection': 'keep-alive',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'Accept': '*/*',
        'Sec-Fetch-Site': 'cross-site',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Dest': 'empty',
        'Accept-Language': 'en-US,en;q=0.9,ru;q=0.8',
    }
    url = "https://www.zerodayinitiative.com/search?q=" + query
    response = functions_tools.make_request(type="get", url=url, headers=headers)
    for line in response.text.split("\n"):
        if "data-url=" in line:
           url = "https://www.zerodayinitiative.com/" + line.split("\"")[1]
           return  {'title': query, 'url': url}
    return None


def get_zdi_search_results_multiple_queries(queries):
    for query in queries:
        print(query)
        result = get_zdi_search_results(query)
        if result is not None:
            return result
    return None

def get_zdi_text_from_url(url):
    headers = {
        'Connection': 'keep-alive',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'Accept': '*/*',
        'Sec-Fetch-Site': 'cross-site',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Dest': 'empty',
        'Accept-Language': 'en-US,en;q=0.9,ru;q=0.8',
    }
    response = functions_tools.make_request(type="get", url=url, headers=headers)
    text = response.text
    if text:
        text = trafilatura.extract(text)

    new_text = ""
    for line in text.split("\n"):
        skip = False
        if re.findall("^\\|", line):  # remove tables
            skip = True
        if re.findall("^- ", line):
            line = re.sub("^- ", "", line)
        if not skip:
            if not re.findall("\\.$", line) and "CVE-" in line:  # looks like a header; don't add new line
                new_text += line + ". "
            else:
                new_text += re.sub("\\.$", ". ", line) + "\n"  # normal line

    return new_text
