from vulristics_code import functions_report_vulnerabilities, functions_profile

name = "test"
report_name = name + ' report'
file_name_prefix = name.lower()

with open('../analyze_cve_list.txt', 'r') as file:
    cves_text = file.read()

with open('../analyze_product_list.txt', 'r') as file:
    products_text = file.read()
file_name = name + "_profile.json"
report_id = name + "_report"
data_sources = ['ms', 'nvd', 'vulners', 'attackerkb']

comments = dict()
comments["hosts"] = ''''''
comments["recent_attack"] = ''''''

rewrite_flag = False

profile_file_path = "data/profiles/" + file_name
functions_profile.save_profile(profile_file_path, report_id, report_name, file_name_prefix, cves_text, products_text,
                               data_sources, comments)
functions_report_vulnerabilities.make_vulnerability_report_for_profile(profile_file_path, rewrite_flag)
