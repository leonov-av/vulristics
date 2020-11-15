import data_vulnerability_classification

def get_vvs_struct_for_cve(cve,cve_data_all,profile):
    # Process CVE-related data and make score structure

    vvs_struct = dict()

    ######## NVD CVSS
    # print(json.dumps(cve_data_all['nvd_cve_data_all'][cve], indent=4))
    # print(cve_data_all['nvd_cve_data_all'][cve]['result']['CVE_Items'][0]['impact']['baseMetricV3']['cvssV3'])
    cvss_base_score = \
    cve_data_all['nvd_cve_data_all'][cve]['result']['CVE_Items'][0]['impact']['baseMetricV3']['cvssV3']['baseScore']
    cvss_base_score_n = int(cvss_base_score) / 10
    cvss_base_score_k = 10
    cvss_base_score_c = "CVSS Base Score"
    cvss_attack_is_network = \
    cve_data_all['nvd_cve_data_all'][cve]['result']['CVE_Items'][0]['impact']['baseMetricV3']['cvssV3']['attackVector']
    if cvss_attack_is_network == "NETWORK":
        cvss_attack_is_network_n = 1.0
        cvss_attack_is_network_c = "CVSS attackVector is NETWORK"
    else:
        cvss_attack_is_network_n = 0
        cvss_attack_is_network_c = "CVSS attackVector is NOT NETWORK"
    cvss_attack_is_network_k = 10
    cvss_attack_ease = \
    cve_data_all['nvd_cve_data_all'][cve]['result']['CVE_Items'][0]['impact']['baseMetricV3']['cvssV3'][
        'attackComplexity']
    if cvss_attack_ease == "LOW":
        cvss_attack_ease_n = 1.0
        cvss_attack_ease_c = "CVSS attackComplexity is LOW"
    else:
        cvss_attack_ease_n = 0.2
        cvss_attack_ease_c = "CVSS attackComplexity is NOT LOW"
    cvss_attack_ease_k = 5
    cvss_exploitability_score = \
    cve_data_all['nvd_cve_data_all'][cve]['result']['CVE_Items'][0]['impact']['baseMetricV3']['exploitabilityScore']
    cvss_exploitability_score_n = int(cvss_exploitability_score) / 10
    cvss_exploitability_score_k = 5
    cvss_exploitability_score_c = "CVSS exploitabilityScore"
    cvss_impact_score = cve_data_all['nvd_cve_data_all'][cve]['result']['CVE_Items'][0]['impact']['baseMetricV3'][
        'impactScore']
    cvss_impact_score_n = int(cvss_impact_score) / 10
    cvss_impact_score_k = 3
    cvss_impact_score_c = "CVSS impactScore"

    ######## Mentioned by vendors
    all_vendors_in_report = len(profile['comments'].keys())
    mentioned = 0
    for vendor in profile['comments']:
        if cve in profile['comments'][vendor]:
            mentioned += 1
    mentioned_by_vm_vendor_n = mentioned / all_vendors_in_report
    mentioned_by_vm_vendor_k = 13
    mentioned_by_vm_vendor_c = "CVE is mentioned by " + str(mentioned) + " from " + str(
        all_vendors_in_report) + " vendors"

    ######## Exploit
    # Currently works only with Vulners data
    is_public_exploit = cve_data_all['vulners_cve_data_all'][cve]['public_exploit']
    if is_public_exploit:
        public_exploit_exists_n = 1.0
        public_exploit_exists_c = "Public exploit is <a href=\"https://vulners.com/cve/" + cve + "\">found at vulners.com</a>"
    else:
        public_exploit_exists_n = 0
        public_exploit_exists_c = "Public exploit is NOT found at vulners.com"
    public_exploit_exists_k = 17

    ######## Product
    # Currently works only with Microsoft data
    vuln_product = cve_data_all['ms_cve_data_all'][cve]['vuln_product']
    vulnerable_product_is_common_n = 0.1
    vulnerable_product_is_common_c = "Other less common product"
    if "Windows" in vuln_product:  # Some standard Windows component
        vulnerable_product_is_common_n = 1.0
        vulnerable_product_is_common_c = "Windows component"
    elif "DNS" in vuln_product:
        vulnerable_product_is_common_n = 0.9
        vulnerable_product_is_common_c = "DNS"
    elif "RDP" in vuln_product:
        vulnerable_product_is_common_n = 0.9
        vulnerable_product_is_common_c = "RDP"
    elif "Office" in vuln_product or "Word" in vuln_product or "Excel" in vuln_product or "Outlook" in vuln_product:
        vulnerable_product_is_common_n = 0.7
        vulnerable_product_is_common_c = "MS Office product"
    elif "SharePoint" in vuln_product:
        vulnerable_product_is_common_n = 0.6
        vulnerable_product_is_common_c = "SharePoint"
    vulnerable_product_is_common_k = 14

    ######## Vulnerability type
    # Currently works only with Microsoft data
    # print(json.dumps(cve_data_all['ms_cve_data_all'][cve]))
    vuln_type = cve_data_all['ms_cve_data_all'][cve]['vuln_type']
    criticality_of_vulnerability_type_n = data_vulnerability_classification.type_to_criticality[vuln_type]
    criticality_of_vulnerability_type_k = 15
    criticality_of_vulnerability_type_c = vuln_type

    vvs_struct = {'components':
        {
            'cvss_base_score': {
                'value': cvss_base_score_n,
                'weight': cvss_base_score_k,
                'comment': cvss_base_score_c
            },
            # 'cvss_attack_is_network': {
            #     'value': cvss_attack_is_network_n,
            #     'weight': cvss_attack_is_network_k,
            #     'comment': cvss_attack_is_network_c
            # },
            # 'cvss_attack_ease': {
            #     'value': cvss_attack_ease_n,
            #     'weight': cvss_attack_ease_k,
            #     'comment': cvss_attack_ease_c
            # },
            # 'cvss_exploitability_score': {
            #     'value': cvss_exploitability_score_n,
            #     'weight': cvss_exploitability_score_k,
            #     'comment': cvss_exploitability_score_c
            # },
            # 'cvss_impact_score': {
            #     'value': cvss_impact_score_n,
            #     'weight': cvss_impact_score_k,
            #     'comment': cvss_impact_score_c
            # },
            'criticality_of_vulnerability_type': {
                'value': criticality_of_vulnerability_type_n,
                'weight': criticality_of_vulnerability_type_k,
                'comment': criticality_of_vulnerability_type_c
            },
            'mentioned_by_vm_vendor': {
                'value': mentioned_by_vm_vendor_n,
                'weight': mentioned_by_vm_vendor_k,
                'comment': mentioned_by_vm_vendor_c
            },
            'vulnerable_product_is_common': {
                'value': vulnerable_product_is_common_n,
                'weight': vulnerable_product_is_common_k,
                'comment': vulnerable_product_is_common_c
            },
            'public_exploit_exists': {
                'value': public_exploit_exists_n,
                'weight': public_exploit_exists_k,
                'comment': public_exploit_exists_c
            },
        }

    }
    score_value = 0
    for component in vvs_struct['components']:
        score_value += vvs_struct['components'][component]['value'] * vvs_struct['components'][component][
            'weight']
    all_weights = 0
    for component in vvs_struct['components']:
        all_weights += vvs_struct['components'][component]['weight']
    score_value = score_value / all_weights
    vvs_struct['value'] = score_value
    if score_value >= 0 and score_value < 0.2:
        level = "Low"
    if score_value >= 0.2 and score_value < 0.4:
        level = "Medium"
    if score_value >= 0.4 and score_value < 0.6:
        level = "High"
    if score_value >= 0.6 and score_value < 0.8:
        level = "Critical"
    if score_value >= 0.8 and score_value <= 1:
        level = "Urgent"
    vvs_struct['level'] = level

    return(vvs_struct)

def get_cve_scores(all_cves,cve_data_all,profile):
    scores_dict = dict()
    for cve in all_cves:
        scores_dict[cve] = get_vvs_struct_for_cve(cve,cve_data_all,profile)
    return(scores_dict)
