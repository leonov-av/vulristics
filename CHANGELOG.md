# Changelog

All notable changes to this project will be documented in this file.

## [1.0.9] - 2024-12-19

- I fixed a very annoying bug in Vulristics when determining the name of a vulnerable product in the CVE description. The product name sometimes appeared inside some words. For example, "Perl" - "properly", "Trie" - "retrieved". Now I check the characters to the left and right of the match. If it is something alphabetic, I ignore it.
- You can now specify CWEs in a custom data source.
- I had some confusion in Changelog dates, I fixed it.

## [1.0.8] - 2024-09-09

Some minor usability improvements by dvppvd:
- Padding was set in the css table to make the html report more readable.
- When you run the utility without parameters, help and examples are displayed. The examples show how to run the utility to analyze MSPT vulnerabilities for a specific month and year, or to analyze an arbitrary set of CVE identifiers.
- Empty lines for the text banner have been added.

## [1.0.7] - 2024-08-13

- Now, if you see exploits in the report that are not actually exploits (but are, for example, detection scripts), you can exclude them. To do this, create a custom data source (json file) for the CVE identifier and add the identifiers of the exploits you want to exclude to the ignore_exploits tag.
- I've added the ability to manage the html report banner via the --result-html-label key. You can specify a banner for Linux Patch Wednesday (lpw), a banner for Microsoft Patch Tuesday (mspt), or the URL of an arbitrary image.

## [1.0.6] - 2024-07-14

- I've made it easier to work with exploit data. Now all Data Sources bring such data in a single format and it is processed uniformly. Including signs of the presence of an exploit in Microsoft CVSS Temporal Vector (I classify them as private exploits). First, I look for the presence of public exploits; if there are none, then private exploits.
- I fixed a bug due to which it was not possible to force the vulnerability type to be set from the Custom Data Source.
- During simplified detection of product names for generated Microsoft vulnerability descriptions, product descriptions can now be pulled up by alternative_names as well.
- I fixed a bug with Vulristics crashing when generating a Microsoft Patch Tuesday report while searching for an MSPT review from Qualys. Now there will be no crash, the Qualys report will simply not be taken into account. For it to be taken into account, you need to add a link in the comments_links. The description format has been added to help and README.

## [1.0.5] - 2024-06-12

- Fixed a bug: vulnerabilities without exploits received the value 0.5, not 0
- Renamed the "Public Exploit Exists" component to the more logical "Exploit Exists"
- Added parameter "-v" or "--version"