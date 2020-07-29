import functions_source_ms_cve
import functions_source_nvd_cve
import functions_source_vulners
import json

cve_id = "CVE-2020-1350"
rewrite_flag = False

print("=== Microsoft ===")
ms_cve_data = functions_source_ms_cve.get_ms_cve_data(cve_id, rewrite_flag)
print(json.dumps(ms_cve_data, indent=2))

print("=== NVD ===")
nvd_cve_data = functions_source_nvd_cve.get_nvd_cve_data(cve_id, rewrite_flag)
print(json.dumps(nvd_cve_data, indent=2))

print("=== Vulners ===")
vulners_cve_data = functions_source_vulners.get_vulners_data(cve_id, rewrite_flag)
print(json.dumps(vulners_cve_data, indent=2))