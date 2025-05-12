**Vulristics** (from “Vulnerability” and “Heuristics”) is an extensible framework for analyzing publicly available information about vulnerabilities. It started as a Microsoft Patch Tuesday reporting tool. Now you can use it to analyse (classify, prioritize) any set of CVEs using the data from Vulners.com, Microsoft website, NVD and AttackerKB.

![vulristics logo](https://github.com/leonov-av/vulristics/blob/master/logo/vulristics_line.png)

## Why is this needed?
Let's say we have a vulnerability ID (CVE ID) and we need to decide whether it is really critical or not. We will probably go to some vulnerability databases (NVD, BDU, CVE page on the Microsoft website, Vulners.com, etc.) and somehow analyze the descriptions and parameters. Right? Such analysis can be quite complex and not so obvious. My idea is to formalize it and make it shareable. It may not be the most efficient way to process data, but it should reflect real human experience, the things that real vulnerability analysts do. This is the main goal.

## What's ready right now?
You can generate the report for the following entities:

* Arbitrary CVE list
```buildoutcfg
./venv/bin/python3 vulristics.py --report-type "cve_list" --cve-project-name "New Project" --cve-list-path "analyze_cve_list.txt" --cve-comments-path "analyze_cve_comments.txt" --cve-data-sources "ms,nvd,epss,vulners,attackerkb,bdu,custom" --rewrite-flag "True" --bdu-use-vulnerability-descriptions-flag "False" --bdu-use-product-names-flag "False"
```
* Custom profile for analysis ([Linux Patch Wednesday custom profile example](https://github.com/leonov-av/linux-patch-wednesday/blob/main/vulristics_profiles/linux_patch_wednesday_may2025.json))
```buildoutcfg
./venv/bin/python3 vulristics.py --report-type "custom_profile" --profile-json-path "linux_patch_wednesday_april2025.json" --cve-data-sources "ms,nvd,epss,vulners,attackerkb,bdu,custom"  --rewrite-flag "False" --bdu-use-vulnerability-descriptions-flag "True" --bdu-use-product-names-flag "False" --result-html-label "lpw"
```
* Microsoft Patch Tuesday ([HTML report example](https://avleonov.com/vulristics_reports/ms_patch_tuesday_april2025_report_with_comments_ext_img.html))
```buildoutcfg
./venv/bin/python3 vulristics.py --report-type "ms_patch_tuesday_extended" --mspt-year 2025 --mspt-month "April" --cve-data-sources "ms,nvd,epss,vulners,attackerkb,bdu,custom" --mspt-comments-links-path "comments_links.txt" --rewrite-flag "True" --bdu-use-vulnerability-descriptions-flag "False" --bdu-use-product-names-flag "False"
 ```

### Example of output
```buildoutcfg
$ ./venv/bin/python3 vulristics.py --report-type "cve_list" --cve-project-name "CVE-2025-24054" --cve-list-path "analyze_cve_list.txt" --cve-data-sources "ms,nvd,epss,vulners,attackerkb,bdu,custom" --rewrite-flag "True" --bdu-use-vulnerability-descriptions-flag "False" --bdu-use-product-names-flag "False"

                       /$$           /$$             /$$     /$$                    
                     | $$          |__/            | $$    |__/                    
 /$$    /$$ /$$   /$$| $$  /$$$$$$  /$$  /$$$$$$$ /$$$$$$   /$$  /$$$$$$$  /$$$$$$$
|  $$  /$$/| $$  | $$| $$ /$$__  $$| $$ /$$_____/|_  $$_/  | $$ /$$_____/ /$$_____/
 \  $$/$$/ | $$  | $$| $$| $$  \__/| $$|  $$$$$$   | $$    | $$| $$      |  $$$$$$ 
  \  $$$/  | $$  | $$| $$| $$      | $$ \____  $$  | $$ /$$| $$| $$       \____  $$
   \  $/   |  $$$$$$/| $$| $$      | $$ /$$$$$$$/  |  $$$$/| $$|  $$$$$$$ /$$$$$$$/
    \_/     \______/ |__/|__/      |__/|_______/    \___/  |__/ \_______/|_______/  

Reading existing profile data/profiles/CVE-2025-24054_profile.json...
Exclude CVEs: 0
No specified products to analyze set in profile, reporting everything
All CVEs: 1
Enabled data sources: ['bdu', 'nvd', 'epss', 'vulners', 'attackerkb', 'custom']
Counting CVE scores...
Collecting NVD CVE data...
1/1 - CVE-2025-24054
Requesting CVE-2025-24054 from NVD website WITH authorization key
Collecting EPSS CVE data...
1/1 - CVE-2025-24054
Requesting CVE-2025-24054 from epss website
Collecting AttackerKB CVE data...
1/1 - CVE-2025-24054
Requesting CVE-2025-24054 from AttackerKB website WITHOUT authorization key
Collecting Vulners CVE data...
1/1 - CVE-2025-24054
Requesting CVE-2025-24054 from Vulners website WITH authorization key
Collecting BDU CVE data...
Updating BDU FSTEC data...
1/1 - CVE-2025-24054
Collecting CUSTOM CVE data...
1/1 - CVE-2025-24054
Combining CVE data...
1/1 CVE-2025-24054
Counting CVE scores...
Making vulnerability reports for each reports config...
Report config: with_comments_ext_img
HTML report generated: reports/cve-2025-24054_report_with_comments_ext_img.html
```

### Options
```buildoutcfg
$ ./venv/bin/python3 vulristics.py -h
usage: vulristics.py [-h] [--report-type REPORT_TYPE] [--mspt-year MSPT_YEAR] [--mspt-month MSPT_MONTH]
                     [--mspt-comments-links-path MSPT_COMMENTS_LINKS_PATH]
                     [--cve-project-name CVE_PROJECT_NAME] [--cve-list-path CVE_LIST_PATH]
                     [--cve-comments-path CVE_COMMENTS_PATH] [--cve-data-sources CVE_DATA_SOURCES]
                     [--profile-json-path PROFILE_JSON_PATH] [--result-formats RESULT_FORMATS]
                     [--result-html-path RESULT_HTML_PATH] [--result-html-label RESULT_HTML_LABEL]
                     [--result-json-path RESULT_JSON_PATH] [--rewrite-flag REWRITE_FLAG]
                     [--vulners-use-github-exploits-flag VULNERS_USE_GITHUB_EXPLOITS_FLAG]
                     [--bdu-use-product-names-flag BDU_USE_PRODUCT_NAMES_FLAG]
                     [--bdu-use-vulnerability-descriptions-flag BDU_USE_VULNERABILITY_DESCRIPTIONS_FLAG]
                     [-v]

An extensible framework for analyzing publicly available information about vulnerabilities

options:
  -h, --help            show this help message and exit
  --report-type REPORT_TYPE
                        Report type (ms_patch_tuesday, ms_patch_tuesday_extended, cve_list or
                        custom_profile)
  --mspt-year MSPT_YEAR
                        Microsoft Patch Tuesday year
  --mspt-month MSPT_MONTH
                        Microsoft Patch Tuesday month
  --mspt-comments-links-path MSPT_COMMENTS_LINKS_PATH
                        Microsoft Patch Tuesday comments links file. Format: "Qualys|Description|URL"
  --cve-project-name CVE_PROJECT_NAME
                        Name of the CVE Project
  --cve-list-path CVE_LIST_PATH
                        Path to the list of CVE IDs
  --cve-comments-path CVE_COMMENTS_PATH
                        Path to the CVE comments file
  --cve-data-sources CVE_DATA_SOURCES
                        Data sources for analysis, e.g. "ms,nvd,bdu,epss,vulners,attackerkb,bdu,custom"
  --profile-json-path PROFILE_JSON_PATH
                        Custom profile for analysis
  --result-formats RESULT_FORMATS
                        Result formats, e.g. "html,json", Default - "html"
  --result-html-path RESULT_HTML_PATH
                        Path to the results file in html format (Default - will be created in reports
                        directory)
  --result-html-label RESULT_HTML_LABEL
                        Additional optional banner for HTML report ("lpw" for the Linux Patch Wednesday
                        banner, "mspt" for the Microsoft Patch Tuesday banner or custom image URL)
  --result-json-path RESULT_JSON_PATH
                        Path to the results file in json format
  --rewrite-flag REWRITE_FLAG
                        Rewrite Flag (True/False, Default - False)
  --vulners-use-github-exploits-flag VULNERS_USE_GITHUB_EXPLOITS_FLAG
                        Use Vulners Github exploits data Flag (True/False, Default - True)
  --bdu-use-product-names-flag BDU_USE_PRODUCT_NAMES_FLAG
                        Use BDU product names Flag (True/False, Default - True)
  --bdu-use-vulnerability-descriptions-flag BDU_USE_VULNERABILITY_DESCRIPTIONS_FLAG
                        Use BDU vulnerability descriptions data Flag (True/False, Default - True)
  -v, --version         show program's version number and exit
```

### Installation
Vulristics is developed and tested on Ubuntu 24.04 LTS, Python 3.12.3
```buildoutcfg
python3 -m venv venv
./venv/bin/pip3 install -r requirements.txt
```

## Where to read more?
* My posts about Vulristics in [avleonov.com blog](https://avleonov.com/category/projects/vulristics/)
* My videos about Vulristics (and vulnerabilities) in [AVLEONOV Media YouTube Channel](https://www.youtube.com/playlist?list=PL2Viq8X7eAaZVQsVG1lcFoEOUr2wRpoha)

If you have good ideas please share them in the [AVLEONOV Chat](https://t.me/avleonovchat). 
The help in coding will be also pretty much appreciated! 😉

## Some obvious warnings (!!)
* This tool is NOT an interface to any particular database.
* The tool makes requests to third-party sources.

So keep in mind that if you actively use it for bulk operations, you may have problems with the owners of these third-party sources, for example, your IP address will simply be banned. So be careful and reasonable!
