from data_ms_patch_tuesday import patch_tuesday_profiles, patch_tuesday_report_configs
import functions_source_ms_cve
import functions_report_ms_patch_tuesday
import re

source_id = "July 2020"

cves_text = patch_tuesday_profiles[source_id]['cves_text']

all_cves = set()
for line in cves_text.split("\n"):
    if re.findall("^CVE", line.upper()):
        all_cves.add(line.upper())

rewrite_flag = False
ms_cve_data_all = dict()
for cve_id in all_cves:
    ms_cve_data = functions_source_ms_cve.get_ms_cve_data(cve_id, rewrite_flag)
    if not ms_cve_data['not_found_error']:
        ms_cve_data_all[cve_id] = ms_cve_data

for report_config_name in patch_tuesday_report_configs:
    functions_report_ms_patch_tuesday.make_pt_report(ms_cve_data_all,
                                                     patch_tuesday_report_configs[report_config_name],
                                                     patch_tuesday_profiles[source_id])
