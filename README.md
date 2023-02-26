**Vulristics** (from “Vulnerability” and “Heuristics”) is an extensible framework for analyzing publicly available information about vulnerabilities. It started as a Microsoft Patch Tuesday reporting tool. Now you can use it to analyse (classify, prioritize) any set of CVEs using the data from Vulners.com, Microsoft website, NVD and AttackerKB.

![vulristics logo](https://github.com/leonov-av/vulristics/blob/master/logo/vulristics_line.png)

## Why is this needed?
Let's say we have a vulnerability ID (CVE ID) and we need to decide whether it is really critical or not. We will probably go to some vulnerability databases (NVD, CVE page on the Microsoft website, Vulners.com, etc.) and somehow analyze the descriptions and parameters. Right? Such analysis can be quite complex and not so obvious. My idea is to formalize it and make it shareable. It may not be the most efficient way to process data, but it should reflect real human experience, the things that real vulnerability analysts do. This is the main goal.

## What's ready right now?
You can generate the report for the following entities:

* Arbitrary CVE list
```buildoutcfg
python3 vulristics.py --report-type "cve_list" --cve-project-name "New Project" --cve-list-path "analyze_cve_list.txt" --cve-comments-path "analyze_cve_comments.txt" --cve-data-sources "ms,nvd,vulners,attackerkb" --rewrite-flag "True"
```
* Microsoft Patch Tuesday ([HTML report example](https://avleonov.com/vulristics_reports/ms_patch_tuesday_november2021_report_with_comments_ext_img.html))
```buildoutcfg
python3 vulristics.py --report-type "ms_patch_tuesday" --mspt-year 2021 --mspt-month "November" --rewrite-flag "True"
```
### Installation
```buildoutcfg
pip3 install -r requirements.txt
```

### Example of output
```buildoutcfg
$ python3 vulristics.py --report-type "cve_list" --cve-project-name "New Project" --cve-list-path "analyze_cve_list.txt" --cve-comments-path "analyze_cve_comments.txt" --cve-data-sources "ms,nvd,vulners,attackerkb"  --rewrite-flag "True"
                      /$$           /$$             /$$     /$$                    
                     | $$          |__/            | $$    |__/                    
 /$$    /$$ /$$   /$$| $$  /$$$$$$  /$$  /$$$$$$$ /$$$$$$   /$$  /$$$$$$$  /$$$$$$$
|  $$  /$$/| $$  | $$| $$ /$$__  $$| $$ /$$_____/|_  $$_/  | $$ /$$_____/ /$$_____/
 \  $$/$$/ | $$  | $$| $$| $$  \__/| $$|  $$$$$$   | $$    | $$| $$      |  $$$$$$ 
  \  $$$/  | $$  | $$| $$| $$      | $$ \____  $$  | $$ /$$| $$| $$       \____  $$
   \  $/   |  $$$$$$/| $$| $$      | $$ /$$$$$$$/  |  $$$$/| $$|  $$$$$$$ /$$$$$$$/
    \_/     \______/ |__/|__/      |__/|_______/    \___/  |__/ \_______/|_______/ 
Reading existing Patch Tuesday profile...
Exclude CVEs: 0
No specified products to analyze set in profile, reporting everything
All CVEs: 1
Counting CVE scores...
Collecting MS CVE data...
Requesting CVE-2021-42284 from Microsoft website
Collecting NVD CVE data...
Requesting CVE-2021-42284 from NVD website
Collecting AttackerKB CVE data...
Requesting CVE-2021-42284 from AttackerKB website WITHOUT authorization key
Collecting Vulners CVE data...
Requesting CVE-2021-42284 from Vulners website WITH authorization key
Counting CVE scores...
Making vulnerability reports for each reports config...
Report config: with_comments_ext_img
Report generated: reports/new_project_report_with_comments_ext_img.html
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
