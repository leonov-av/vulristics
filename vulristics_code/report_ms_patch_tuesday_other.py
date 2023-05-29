from vulristics_code import functions_report_vulnerabilities, functions_profile_ms_patch_tuesday, functions_profile

file_name = "ms_patch_tuesday_other_Q1_2021.json"
report_id = "ms_patch_tuesday_other_Q1_2021"
report_name = 'Microsoft Patch Tuesday Q1 Other report'
file_name_prefix = "ms_patch_tuesday_other_Q1_2021"

from_date = "2021-01-01"
to_date = "2021-03-31"
patch_tuesdays = [("2021", "January"), ("2021", "February"), ("2021", "March")]

cves_text = functions_profile_ms_patch_tuesday.get_other_ms_cves(from_date, to_date, patch_tuesdays)
data_sources = None
comments = None

rewrite_flag = False

profile_file_path = "data/profiles/" + file_name
functions_profile.save_profile(profile_file_path, report_id, report_name, file_name_prefix, cves_text,
                               data_sources, comments)
functions_report_vulnerabilities.make_vulnerability_report_for_profile(profile_file_path, rewrite_flag)
