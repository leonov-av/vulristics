import json
import os

def get_custom_cve_data_raw(cve_id):
    file_path = "data/custom_cve/" + cve_id + ".json"
    if os.path.exists(file_path):
        f = open("data/custom_cve/" + cve_id + ".json", "r")
        custom_cve_data = json.loads(f.read())
        f.close()
        return custom_cve_data
    else:
        return {}

def get_custom_cve_data(cve_id, source_config):
    custom_cve_data = {"raw": get_custom_cve_data_raw(cve_id)}
    for param in ['description', 'cvss_base_score', 'wild_exploited', 'wild_exploited_sources',
                  'public_exploit', 'public_exploit_sources', 'epss', 'epss_percentile',
                  'vulnerability_type', 'product_name', 'ignore_exploits']:
        if param in custom_cve_data['raw']:
            custom_cve_data[param] = custom_cve_data['raw'][param]
    return custom_cve_data