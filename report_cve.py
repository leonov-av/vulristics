import functions_profile
import functions_report_vulnerabilities

file_name = "test_cve_profile.json"
report_id = "test_cve_report"
report_name = 'CVE report'
file_name_prefix = "test_cve_report"
cves_text = '''CVE-2021-3156
CVE-2021-21972
CVE-2021-21973
CVE-2021-21974'''
data_sources = ['vulners']
comments = []

rewrite_flag = True

profile_file_path = "data/profiles/" + file_name
functions_profile.save_profile(file_name, report_id, report_name, file_name_prefix, cves_text, data_sources, comments)
functions_report_vulnerabilities.make_vulnerability_report_for_profile(profile_file_path, rewrite_flag)