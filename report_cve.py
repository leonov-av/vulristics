import functions_profile
import functions_report_vulnerabilities

file_name = "test_cve_profile.json"
report_id = "test_cve_report"
report_name = 'CVE report'
file_name_prefix = "test_cve_report"
cves_text = '''CVE-2020-1350
CVE-2021-3156'''

comments = []

rewrite_flag = True

functions_profile.save_profile(file_name, report_id, report_name, file_name_prefix, cves_text, comments)
functions_report_vulnerabilities.make_vulnerability_report_for_profile(file_name, rewrite_flag)
