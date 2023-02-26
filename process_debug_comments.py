# month = "April"
# year = "2022"
# query = month + " " + year + " " + "Patch Tuesday"
# print(query)
# tenable_link = functions_source_analytic_sites.get_tenable_link(query)
# print(tenable_link)

# month = "April"
# year = "2022"
# query = month + " " + year + " " + "Patch Tuesday"
# print(query)
# qualys_link = functions_source_analytic_sites.get_qualys_link(query)
# print(qualys_link)

# month = "April"
# year = "2022"
# queries = [
#     "site:https://www.zerodayinitiative.com/blog THE " + month + " " + year + " SECURITY UPDATE REVIEW",
#     "site:https://www.thezdi.com/blog Microsoft Patches for " + month + " " + year
# ]
# zdi_link = functions_source_analytic_sites.get_duckduckgo_search_results_multiple_queries(queries)
# print(zdi_link)

import functions_source_analytic_sites

url = "https://blog.qualys.com/vulnerabilities-threat-research/patch-tuesday/2023/02/14/the-february-2023-patch-tuesday-security-update-review"
qualys_text = functions_source_analytic_sites.get_qualys_text_from_url(url)
qualys_text = functions_source_analytic_sites.process_qualys_text(qualys_text)
print(qualys_text)