from data_ms_patch_tuesday import patch_tuesday_profiles, patch_tuesday_report_configs
import functions_source_ms_cve
import functions_report_ms_patch_tuesday
import re

source_id = "April 2020"
#source_id = "Shadow August 2020"

cves_exclude = set()
if 'cves_exclude_text' in patch_tuesday_profiles[source_id]:
    cves_exclude_text = patch_tuesday_profiles[source_id]['cves_exclude_text']
    for line in cves_exclude_text.split("\n"):
        if re.findall("^CVE", line.upper()):
            cves_exclude.add(line.upper())

cves_text = patch_tuesday_profiles[source_id]['cves_text']

all_cves = set()
for line in cves_text.split("\n"):
    if re.findall("^CVE", line.upper()):
        if line.upper() not in cves_exclude:
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
