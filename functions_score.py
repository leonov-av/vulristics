import data_vulnerability_classification

def get_level(score_value):
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
    return(level)

def get_vvs_struct_for_cve(cve,cve_data_all,profile = False):
    # Process CVE-related data and make score structure
    vvs_struct = dict()
    use_comments = False

    ######## NVD CVSS
    # print(json.dumps(cve_data_all['nvd_cve_data_all'][cve], indent=4))
    # print(cve_data_all['nvd_cve_data_all'][cve]['result']['CVE_Items'][0]['impact']['baseMetricV3']['cvssV3'])
    cvss_base_score = 0
    if 'impact' in cve_data_all['nvd_cve_data_all'][cve]['result']['CVE_Items'][0]:
        cvss_base_score = cve_data_all['nvd_cve_data_all'][cve]['result']['CVE_Items'][0]['impact']['baseMetricV3']['cvssV3']['baseScore']
    cvss_base_score_n = int(cvss_base_score) / 10
    cvss_base_score_k = 10
    # Rating CVSS Score
    # Low 0.1 - 3.9
    # Medium 4.0 - 6.9
    # High 7.0 - 8.9
    # Critical 9.0 - 10.0
    cvss_rating = "N/A"
    if int(cvss_base_score) > 0 and int(cvss_base_score) < 4:
        cvss_rating = "Low"
    elif int(cvss_base_score) >= 4 and int(cvss_base_score) < 7:
        cvss_rating = "Medium"
    elif int(cvss_base_score) >= 7 and int(cvss_base_score) < 9:
        cvss_rating = "High"
    elif int(cvss_base_score) >= 9:
        cvss_rating = "Critical"
    cvss_base_score_c = "NVD Vulnerability Severity Rating is " + cvss_rating

    cvss_attack_is_network = "n/a"
    if 'impact' in cve_data_all['nvd_cve_data_all'][cve]['result']['CVE_Items'][0]:
        cvss_attack_is_network = cve_data_all['nvd_cve_data_all'][cve]['result']['CVE_Items'][0]['impact']['baseMetricV3']['cvssV3']['attackVector']
    if cvss_attack_is_network == "NETWORK":
        cvss_attack_is_network_n = 1.0
        cvss_attack_is_network_c = "CVSS attackVector is NETWORK"
    else:
        cvss_attack_is_network_n = 0
        cvss_attack_is_network_c = "CVSS attackVector is NOT NETWORK"
    cvss_attack_is_network_k = 10
    cvss_attack_ease = "n/a"
    if 'impact' in cve_data_all['nvd_cve_data_all'][cve]['result']['CVE_Items'][0]:
        cvss_attack_ease = cve_data_all['nvd_cve_data_all'][cve]['result']['CVE_Items'][0]['impact']['baseMetricV3']['cvssV3']['attackComplexity']
    if cvss_attack_ease == "LOW":
        cvss_attack_ease_n = 1.0
        cvss_attack_ease_c = "CVSS attackComplexity is LOW"
    else:
        cvss_attack_ease_n = 0.2
        cvss_attack_ease_c = "CVSS attackComplexity is NOT LOW"
    cvss_attack_ease_k = 5
    cvss_exploitability_score = 0
    if 'impact' in cve_data_all['nvd_cve_data_all'][cve]['result']['CVE_Items'][0]:
        cvss_exploitability_score = cve_data_all['nvd_cve_data_all'][cve]['result']['CVE_Items'][0]['impact']['baseMetricV3']['exploitabilityScore']
    cvss_exploitability_score_n = int(cvss_exploitability_score) / 10
    cvss_exploitability_score_k = 5
    cvss_exploitability_score_c = "CVSS exploitabilityScore"
    cvss_impact_score = 0
    if 'impact' in cve_data_all['nvd_cve_data_all'][cve]['result']['CVE_Items'][0]:
        cvss_impact_score = cve_data_all['nvd_cve_data_all'][cve]['result']['CVE_Items'][0]['impact']['baseMetricV3']['impactScore']
    cvss_impact_score_n = int(cvss_impact_score) / 10
    cvss_impact_score_k = 3
    cvss_impact_score_c = "CVSS impactScore"

    ######## Mentioned by vendors
    if use_comments:
        all_vendors_in_report = len(profile['comments'].keys())
        mentioned = 0
        for vendor in profile['comments']:
            if cve in profile['comments'][vendor]:
                mentioned += 1
        mentioned_by_vm_vendor_n = mentioned / all_vendors_in_report
        mentioned_by_vm_vendor_k = 13
        mentioned_by_vm_vendor_c = "CVE is mentioned by " + str(mentioned) + " from " + str(
            all_vendors_in_report) + " vendors"

    ######## Public Exploit
    # Currently works only with Vulners data
    is_public_exploit = cve_data_all['vulners_cve_data_all'][cve]['public_exploit']
    if is_public_exploit:
        public_exploit_exists_n = 1.0
        public_exploit_exists_c = "Public exploit is <a href=\"https://vulners.com/cve/" + cve + "\">found at vulners.com</a>"
    else:
        public_exploit_exists_n = 0
        public_exploit_exists_c = "Public exploit is NOT found at vulners.com"
    public_exploit_exists_k = 17

    ######## Wild Exploit
    # Currently with Vulners and MS data
    wild_exploited = False
    if not wild_exploited:
        if cve in cve_data_all['vulners_cve_data_all']:
            if 'wild_exploited' in cve_data_all['vulners_cve_data_all'][cve]:
                if cve_data_all['vulners_cve_data_all'][cve]['wild_exploited']:
                    wild_exploited = True
                    wild_exploited_n = 1.0
                    wild_exploited_c = "Exploitation in the wild is <a href=\"https://vulners.com/cve/" + cve + "\">found at vulners.com</a>"
    if not wild_exploited:
        if cve in cve_data_all['ms_cve_data_all']:
            if 'exploited' in cve_data_all['ms_cve_data_all'][cve]:
                if cve_data_all['ms_cve_data_all'][cve]['exploited'] == "Yes":
                    wild_exploited = True
                    wild_exploited_n = 1.0
                    wild_exploited_c = "Exploitation in the wild is mentioned at <a href=\"https://msrc.microsoft.com/update-guide/vulnerability/" + cve + "\">Microsoft website</a>"
    if not wild_exploited:
        wild_exploited_n = 0
        wild_exploited_c = "Exploitation in the wild is NOT found at vulners.com and Microsoft website"
    wild_exploited_k = 18

    ######## Product
    # Currently works only with Microsoft data
    if cve in cve_data_all['ms_cve_data_all']:
        vuln_product = cve_data_all['ms_cve_data_all'][cve]['vuln_product']
        vulnerable_product_is_common_n = 0.1
        vulnerable_product_is_common_c = "Other less common product"
    else:
        vuln_product = "Unknown product"
        vulnerable_product_is_common_n = 0
        vulnerable_product_is_common_c = "Unknown product"
    if "Windows" in vuln_product:  # Some standard Windows component
        vulnerable_product_is_common_n = 1.0
        vulnerable_product_is_common_c = "Windows component"
    elif "Kerberos" in vuln_product:
        vulnerable_product_is_common_n = 1.0
        vulnerable_product_is_common_c = "Kerberos"
    elif "DNS" in vuln_product:
        vulnerable_product_is_common_n = 0.9
        vulnerable_product_is_common_c = "DNS"
    elif "RDP" in vuln_product or "Remote Desktop Protocol" in vuln_product:
        vulnerable_product_is_common_n = 0.9
        vulnerable_product_is_common_c = "RDP"
    elif "Office" in vuln_product or "Word" in vuln_product or "Excel" in vuln_product or "Outlook" in vuln_product or "Office" in vuln_product or "Teams" in vuln_product:
        vulnerable_product_is_common_n = 0.7
        vulnerable_product_is_common_c = "MS Office product"
    elif "Office" in vuln_product or "Chakra" in vuln_product or "Internet Explorer" in vuln_product or "Microsoft Browser" in vuln_product or "Scripting Engine" in vuln_product:
        vulnerable_product_is_common_n = 0.7
        vulnerable_product_is_common_c = "MS Internet Browser"
    elif "SharePoint" in vuln_product:
        vulnerable_product_is_common_n = 0.6
        vulnerable_product_is_common_c = "SharePoint"
    elif "DirectX" in vuln_product:
        vulnerable_product_is_common_n = 0.9
        vulnerable_product_is_common_c = "DirectX"
    elif "Visual Studio" in vuln_product:
        vulnerable_product_is_common_n = 0.6
        vulnerable_product_is_common_c = "Visual Studio"
    elif "Hyper-V" in vuln_product:
        vulnerable_product_is_common_n = 0.6
        vulnerable_product_is_common_c = "Hyper-V"
    elif "Microsoft Exchange" in vuln_product:
        vulnerable_product_is_common_n = 0.8
        vulnerable_product_is_common_c = "Microsoft Exchange"
    elif "Azure" in vuln_product:
        vulnerable_product_is_common_n = 0.4
        vulnerable_product_is_common_c = "Azure Sphere"
    elif "Microsoft Dynamics 365" in vuln_product:
        vulnerable_product_is_common_n = 0.6
        vulnerable_product_is_common_c = "Microsoft Dynamics 365"
    elif "Microsoft Defender" in vuln_product:
        vulnerable_product_is_common_n = 0.9
        vulnerable_product_is_common_c = "Microsoft Defender"
    vulnerable_product_is_common_k = 14

    ######## Vulnerability type
    # Currently works only with Microsoft data
    # print(json.dumps(cve_data_all['ms_cve_data_all'][cve]))
    if cve in cve_data_all['ms_cve_data_all']:
        vuln_type = cve_data_all['ms_cve_data_all'][cve]['vuln_type']
    else:
        vuln_type = "Unknown vulnerability type"
    criticality_of_vulnerability_type_n = data_vulnerability_classification.type_to_criticality[vuln_type]
    criticality_of_vulnerability_type_k = 15
    criticality_of_vulnerability_type_c = vuln_type

    vvs_struct['components'] = dict()

    if use_comments:
        vvs_struct['components']['mentioned_by_vm_vendor'] = {
            'value': mentioned_by_vm_vendor_n,
            'weight': mentioned_by_vm_vendor_k,
            'comment': mentioned_by_vm_vendor_c
        }
    vvs_struct['components']['CVSS Base Score'] = {
        'value': cvss_base_score_n,
        'weight': cvss_base_score_k,
        'comment': cvss_base_score_c
    }
    # vvs_struct['components']['CVSS Attack is Network'] = {
    #     'value': cvss_attack_is_network_n,
    #     'weight': cvss_attack_is_network_k,
    #     'comment': cvss_attack_is_network_c
    # }
    # vvs_struct['components']['CVSS Attack Ease'] = {
    #     'value': cvss_attack_ease_n,
    #     'weight': cvss_attack_ease_k,
    #     'comment': cvss_attack_ease_c
    # }
    # vvs_struct['components']['CVSS Exploitablity Score'] = {
    #     'value': cvss_exploitability_score_n,
    #     'weight': cvss_exploitability_score_k,
    #     'comment': cvss_exploitability_score_c
    # }
    # vvs_struct['components']['CVSS Impact Score'] = {
    #     'value': cvss_impact_score_n,
    #     'weight': cvss_impact_score_k,
    #     'comment': cvss_impact_score_c
    # }
    vvs_struct['components']['Criticality of Vulnerability Type'] = {
        'value': criticality_of_vulnerability_type_n,
        'weight': criticality_of_vulnerability_type_k,
        'comment': criticality_of_vulnerability_type_c
    }
    vvs_struct['components']['Vulnerable Product is Common'] = {
        'value': vulnerable_product_is_common_n,
        'weight': vulnerable_product_is_common_k,
        'comment': vulnerable_product_is_common_c
    }
    vvs_struct['components']['Public Exploit Exists'] = {
        'value': public_exploit_exists_n,
        'weight': public_exploit_exists_k,
        'comment': public_exploit_exists_c
    }
    vvs_struct['components']['Exploited in the Wild'] = {
        'value': wild_exploited_n,
        'weight': wild_exploited_k,
        'comment': wild_exploited_c
    }

    for component in vvs_struct['components']:
        vvs_struct['components'][component]['level'] = get_level(vvs_struct['components'][component]['value'])

    score_value = 0
    for component in vvs_struct['components']:
        score_value += vvs_struct['components'][component]['value'] * vvs_struct['components'][component]['weight']
    all_weights = 0
    for component in vvs_struct['components']:
        all_weights += vvs_struct['components'][component]['weight']
    score_value = score_value / all_weights
    vvs_struct['value'] = score_value
    vvs_struct['level'] = get_level(score_value)

    return(vvs_struct)

def get_cve_scores(all_cves,cve_data_all,profile):
    scores_dict = dict()
    for cve in all_cves:
        scores_dict[cve] = get_vvs_struct_for_cve(cve,cve_data_all,profile)
    return(scores_dict)
