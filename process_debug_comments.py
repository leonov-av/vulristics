# import vulristics_code.functions_source_analytic_sites

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

# month = "November"
# year = "2023"
# queries = [
#     "THE " + month + " " + year + " SECURITY UPDATE REVIEW",
#     "Microsoft Patches for " + month + " " + year
# ]
# zdi_link = vulristics_code.functions_source_analytic_sites.get_zdi_search_results_multiple_queries(queries)
# print(zdi_link)

# from vulristics_code import functions_source_analytic_sites
#
# url = "https://blog.qualys.com/vulnerabilities-threat-research/patch-tuesday/2023/02/14/the-february-2023-patch-tuesday-security-update-review"
# qualys_text = functions_source_analytic_sites.get_qualys_text_from_url(url)
# qualys_text = functions_source_analytic_sites.process_qualys_text(qualys_text)
# print(qualys_text)

# from vulristics_code import functions_source_analytic_sites
#
# url = "https://nakedsecurity.sophos.com/2023/07/12/microsoft-patches-four-zero-days-finally-takes-action-against-crimeware-kernel-drivers/"
# source_text = functions_source_analytic_sites.get_text_from_url(url)
# print(source_text)