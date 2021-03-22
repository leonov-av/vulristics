# Vulristics
Vulristics (from “Vulnerability” and “Heuristics”) is an extensible framework for analyzing publicly available information about vulnerabilities. It started as a Microsoft Patch Tuesday reporting tool. Now you can use it to analyse any set of CVEs using the data from Vulners.com, Microsoft website, NVD and AttackerKB.

## Why is this needed?
Let's say we have a vulnerability ID (CVE ID) and we need to decide whether it is really critical or not. We will probably go to some vulnerability databases (NVD, CVE page on the , etc.) and somehow analyze the descriptions and parameters. Right? Such analysis can be quite complex and not so obvious. My idea is to formalize it and make it shareable. It may not be the most efficient way to process data, but it should reflect real human experience, the things that real vulnerability analysts do. This is the main goal.

![vulristics logo](https://github.com/leonov-av/vulristics/blob/master/logo/vulristics_line.png)

## What's ready right now?
Currently, there are the following scripts available:

1. report_ms_patch_tuesday.py - make html report for Microsoft Patch Tuesday CVEs
2. report_ms_patch_tuesday_other.py - make html report for Microsoft CVEs not in Patch Tuesday 
3. report_cve.py - make html report for any set of CVEs
4. report_daily_exploits.py - make daily exploits report that I use for my news channel https://t.me/avleonovnews.

If you have good ideas please share them in the https://t.me/avleonovchat. 
The help in coding will be also pretty much appreciated! 😉

## Some obvious warnings (!!)
* This tool is NOT an interface to any particular database.
* The tool makes requests to third-party sources.

So keep in mind that if you actively use it for bulk operations, you may have problems with the owners of these third-party sources, for example, your IP address will simply be banned. So be careful and reasonable!
