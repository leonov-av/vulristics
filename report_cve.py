import functions_profile
import functions_report_vulnerabilities

report_name = 'CVE NCSC JOINT report'
# https://www.ncsc.gov.uk/news/joint-advisory-further-ttps-associated-with-svr-cyber-actors
file_name_prefix = "cve_ncsc_joint"

with open('csv_list_to_analyze.txt', 'r') as file:
    cves_text = file.read()


with open('products_to_analyze.txt', 'r') as file:
    products_text = file.read()
file_name = "test_cve_profile.json"
report_id = "test_cve_report"
data_sources = ['ms', 'nvd', 'vulners', 'attackerkb']

comments = []

rewrite_flag = False

profile_file_path = "data/profiles/" + file_name
functions_profile.save_profile(profile_file_path, report_id, report_name, file_name_prefix, cves_text, products_text,
                               data_sources, comments)
functions_report_vulnerabilities.make_vulnerability_report_for_profile(profile_file_path, rewrite_flag)
