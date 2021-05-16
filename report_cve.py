import functions_profile
import functions_report_vulnerabilities

report_name = 'CVE NCSC JOINT report'
# https://www.ncsc.gov.uk/news/joint-advisory-further-ttps-associated-with-svr-cyber-actors
file_name_prefix = "cve_ncsc_joint"
cves_text = '''CVE-2018-13379
CVE-2019-1653
CVE-2019-2725
CVE-2019-9670
CVE-2019-11510
CVE-2019-19781
CVE-2019-7609
CVE-2020-4006
CVE-2020-5902
CVE-2020-14882
CVE-2021-21972'''

file_name = "test_cve_profile.json"
report_id = "test_cve_report"
data_sources = ['ms', 'nvd', 'vulners', 'attackerkb']

comments = []

rewrite_flag = False

profile_file_path = "data/profiles/" + file_name
functions_profile.save_profile(profile_file_path, report_id, report_name, file_name_prefix, cves_text,
                               data_sources, comments)
functions_report_vulnerabilities.make_vulnerability_report_for_profile(profile_file_path, rewrite_flag)
