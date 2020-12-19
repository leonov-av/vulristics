# Vulristics
Extensible framework for analyzing publicly available information about vulnerabilities

I decided to release my Microsoft Patch Tuesday reporting tool as part of a larger open source project. I named it Vulristics (from “Vulnerability” and “Heuristics”). Let's say we have a vulnerability ID (CVE ID) and we need to decide whether it is really critical or not. We will probably go to some vulnerability databases (NVD, CVE page on the Microsoft website, Vulners.com, etc.) and somehow analyze the descriptions and parameters. Right?  Such analysis can be quite complex and not so obvious. My idea is to formalize it and make it shareable. It may not be the most efficient way to process data, but it should reflect real human experience, the things that real vulnerability analysts do. This is the main goal.

![vulristics logo](https://github.com/leonov-av/vulristics/blob/master/logo/vulristics_line.png)

Currently, there are the following scripts available:

1. report_ms_patch_tuesday.py - analyze and group Microsoft Patch Tuesday CVEs.
2. report_cve.py - collect and preprocess CVE ID-related data from NVD, Microsoft.com and Vulners. 
3. report_daily_exploits.py - daily exploits report I use for my news channel https://t.me/avleonovnews.

Of course, we can do much more than that. I have plans to add:

* analysis of the vulnerability description based on keywords and phrases (it's good that such descriptions usually have a fairly regular structure)
* analysis of references
* danger and relevance metrics counting (vulnerability quadrants)
and so on.

If you have good ideas please share them in the https://t.me/avleonovchat. 
The help in coding will be also pretty much appreciated! 😉

Finally, some obvious warnings:

* This tool is NOT an interface to any particular database.
* The tool makes requests to third-party sources.

So keep in mind that if you actively use it for bulk operations, you may have problems with the owners of these third-party sources, for example, your IP address will simply be banned. So be careful and reasonable!
