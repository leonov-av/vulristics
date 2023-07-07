from vulristics_code import data_exclusions, data_redefinitions, functions_tools, data_classification_vulnerability_types


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
    return level

def get_vvs_struct_for_cve(cve, cve_data_all, profile):
    # Process CVE-related data and make score structure
    vvs_struct = dict()
    use_comments = False

    ######## CVSS Base Score from NVD, Microsoft or Vulners
    if not cve_data_all['combined_cve_data_all'][cve]['cvss_base_score']:
        cve_data_all['combined_cve_data_all'][cve]['cvss_base_score'] = "Unknown CVSS Base Score"
    if cve_data_all['combined_cve_data_all'][cve]['cvss_base_score'] == "Unknown CVSS Base Score":
        cvss_base_score = 0
        cvss_base_score_c = "CVSS Base Score is NA. No data."
    else:
        cvss_base_score = cve_data_all['combined_cve_data_all'][cve]['cvss_base_score']
        cvss_base_score_c = "CVSS Base Score is " + str(cvss_base_score) + ". " \
                            + cve_data_all['combined_cve_data_all'][cve]['cvss_base_score_detection_comment']
    if cve in data_redefinitions.cvss:
        cvss_base_score = data_redefinitions.cvss[cve]['cvss_base_score']
        cvss_base_score_c = "CVSS Base Score is " + str(cvss_base_score) + ". " \
                            + data_redefinitions.cvss[cve]['cvss_base_score_detection_comment']
    cvss_base_score_n = round(float(cvss_base_score) / 10, 1)
    cvss_base_score_k = 10

    cvss_attack_is_network = "n/a"
    if 'nvd_cve_data_all' in cve_data_all:
        if 'result' in cve_data_all['nvd_cve_data_all'][cve]:
            if 'impact' in cve_data_all['nvd_cve_data_all'][cve]['result']['CVE_Items'][0]:
                if 'baseMetricV3' in cve_data_all['nvd_cve_data_all'][cve]['result']['CVE_Items'][0]['impact']:
                    cvss_attack_is_network = cve_data_all['nvd_cve_data_all'][cve]['result']['CVE_Items'][0]['impact']['baseMetricV3']['cvssV3']['attackVector']
    if cvss_attack_is_network == "NETWORK":
        cvss_attack_is_network_n = 1.0
        cvss_attack_is_network_c = "CVSS attackVector is NETWORK"
    else:
        cvss_attack_is_network_n = 0
        cvss_attack_is_network_c = "CVSS attackVector is NOT NETWORK"
    cvss_attack_is_network_k = 10
    cvss_attack_ease = "n/a"
    if 'nvd_cve_data_all' in cve_data_all:
        if 'result' in cve_data_all['nvd_cve_data_all'][cve]:
            if 'impact' in cve_data_all['nvd_cve_data_all'][cve]['result']['CVE_Items'][0]:
                if 'baseMetricV3' in cve_data_all['nvd_cve_data_all'][cve]['result']['CVE_Items'][0]['impact']:
                    cvss_attack_ease = cve_data_all['nvd_cve_data_all'][cve]['result']['CVE_Items'][0]['impact']['baseMetricV3']['cvssV3']['attackComplexity']
    if cvss_attack_ease == "LOW":
        cvss_attack_ease_n = 1.0
        cvss_attack_ease_c = "CVSS attackComplexity is LOW"
    else:
        cvss_attack_ease_n = 0.2
        cvss_attack_ease_c = "CVSS attackComplexity is NOT LOW"
    cvss_attack_ease_k = 5
    cvss_exploitability_score = 0
    if 'nvd_cve_data_all' in cve_data_all:
        if 'result' in cve_data_all['nvd_cve_data_all'][cve]:
            if 'impact' in cve_data_all['nvd_cve_data_all'][cve]['result']['CVE_Items'][0]:
                if 'baseMetricV3' in cve_data_all['nvd_cve_data_all'][cve]['result']['CVE_Items'][0]['impact']:
                    cvss_exploitability_score = cve_data_all['nvd_cve_data_all'][cve]['result']['CVE_Items'][0]['impact']['baseMetricV3']['exploitabilityScore']
    cvss_exploitability_score_n = int(cvss_exploitability_score) / 10
    cvss_exploitability_score_k = 5
    cvss_exploitability_score_c = "CVSS exploitabilityScore"
    cvss_impact_score = 0
    if 'nvd_cve_data_all' in cve_data_all:
        if 'result' in cve_data_all['nvd_cve_data_all'][cve]:
            if 'impact' in cve_data_all['nvd_cve_data_all'][cve]['result']['CVE_Items'][0]:
                if 'baseMetricV3' in cve_data_all['nvd_cve_data_all'][cve]['result']['CVE_Items'][0]['impact']:
                    cvss_impact_score = cve_data_all['nvd_cve_data_all'][cve]['result']['CVE_Items'][0]['impact']['baseMetricV3']['impactScore']
    cvss_impact_score_n = int(cvss_impact_score) / 10
    cvss_impact_score_k = 3
    cvss_impact_score_c = "CVSS impactScore"

    ######## EPSS Score
    if 'epss_cve_data_all' in cve_data_all:
        epss_percentile = cve_data_all['epss_cve_data_all'][cve]['epss_percentile']
        epss_probability = cve_data_all['epss_cve_data_all'][cve]['epss']
        epss_score_n = round(epss_percentile, 1)
        epss_score_k = 10
        epss_score_c = "EPSS Probability is " + str(epss_probability) + ", EPSS Percentile is " + str(epss_percentile)
    else:
        epss_percentile = 0
        epss_probability = 0
        epss_score_n = round(epss_percentile, 1)
        epss_score_k = 10
        epss_score_c = "EPSS data is not available"


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
    is_public_exploit = False
    if 'vulners_cve_data_all' in cve_data_all:
        if cve in cve_data_all['vulners_cve_data_all']:
            if 'public_exploit' in cve_data_all['vulners_cve_data_all'][cve]:
                is_public_exploit = cve_data_all['vulners_cve_data_all'][cve]['public_exploit']

    # Exclusions
    new_public_exploit_sources = list()
    if is_public_exploit:
        for exploit_source in cve_data_all['vulners_cve_data_all'][cve]['public_exploit_sources']:
            exploit_id = exploit_source['id'] + "_" + exploit_source['type']
            if not exploit_id.lower() in data_exclusions.exclusions['not_an_exploit']:
                new_public_exploit_sources.append(exploit_source)
                is_public_exploit = True

    if 'vulners_cve_data_all' in cve_data_all:
        cve_data_all['vulners_cve_data_all'][cve]['public_exploit_sources'] = new_public_exploit_sources
        if new_public_exploit_sources == list():
            is_public_exploit = False
            cve_data_all['vulners_cve_data_all'][cve]['public_exploit'] = False
        if 'ms_cve_data_all' in cve_data_all:
            if cve in cve_data_all['ms_cve_data_all']:
                if cve_data_all['ms_cve_data_all'][cve]['public_exploit']:
                    is_public_exploit = True

    if is_public_exploit:
        public_exploit_exists_n = 1.0
        links_str = list()
        comment_exists = False
        if 'vulners_cve_data_all' in cve_data_all:
            if cve_data_all['vulners_cve_data_all'][cve]['public_exploit'] and not comment_exists:
                for exploit_data in cve_data_all['vulners_cve_data_all'][cve]['public_exploit_sources']:
                    links_str.append("<a href=\"https://vulners.com/" + exploit_data['type'] + "/"
                                     + exploit_data['id'] + "\">" + exploit_data['title'] + "</a>")
                public_exploit_exists_c = "The existence of a publicly available exploit is mentioned on Vulners website (" + ", ".join(links_str) + ")"
                comment_exists = True
        if 'ms_cve_data_all' in cve_data_all:
            if cve in cve_data_all['ms_cve_data_all']:
                if cve_data_all['ms_cve_data_all'][cve]['public_exploit'] and not comment_exists:
                    public_exploit_exists_n = cve_data_all['ms_cve_data_all'][cve]['public_exploit_level']
                    public_exploit_exists_c = "The exploit's existence is mentioned in Microsoft CVSS Temporal Metrics (" +\
                                              cve_data_all['ms_cve_data_all'][cve]['public_exploit_level_name'] + ")"
                    comment_exists = True
    else:
        public_exploit_exists_n = 0
        public_exploit_exists_c = "The exploit's existence is NOT mentioned on Vulners and Microsoft websites."
    public_exploit_exists_k = 17

    ######## Wild Exploit
    # Currently with Vulners and MS data
    wild_exploited = False
    mentioned = list()

    flag_vulners_attackerkb = False
    flag_vulners_cisa = False
    flag_vulners_other = False
    flag_attackerkb = False
    flag_ms_cve_data_all = False

    if 'vulners_cve_data_all' in cve_data_all:
        if cve in cve_data_all['vulners_cve_data_all']:
            if 'wild_exploited' in cve_data_all['vulners_cve_data_all'][cve]:
                if cve_data_all['vulners_cve_data_all'][cve]['wild_exploited']:
                    wild_exploited = True
                    wild_exploited_n = 1.0
                    links_str = list()
                    for ref in cve_data_all['vulners_cve_data_all'][cve]['wild_exploited_sources']:
                        for ref_id in ref['idList']:
                            if ref['type'] == "attackerkb":
                                type = "AttackerKB"
                                flag_vulners_attackerkb = True
                            elif ref['type'] == "cisa":
                                type = "CISA"
                                flag_vulners_cisa = True
                            else:
                                type = ref['type']
                                flag_vulners_other = True
                            links_str.append("<a href=\"https://vulners.com/" + ref['type'] + "/" +
                                             ref_id + "\">" + type + "</a> object")
                    mentioned.append("Vulners (" + ", ".join(links_str) + ")")

    if 'attackerkb_cve_data_all' in cve_data_all:
        if cve in cve_data_all['attackerkb_cve_data_all']:
            if 'Exploited in the Wild' in cve_data_all['attackerkb_cve_data_all'][cve]:
                if cve_data_all['attackerkb_cve_data_all'][cve]['Exploited in the Wild']:
                    for url in cve_data_all['attackerkb_cve_data_all'][cve]['urls']:
                        wild_exploited = True
                        wild_exploited_n = 1.0
                        flag_attackerkb = True
                        mentioned.append("<a href=\"" + url + "\">AttackerKB</a>")

    if 'ms_cve_data_all' in cve_data_all:
        if cve in cve_data_all['ms_cve_data_all']:
            if 'exploited' in cve_data_all['ms_cve_data_all'][cve]:
                if cve_data_all['ms_cve_data_all'][cve]['exploited'] == "Yes":
                    wild_exploited = True
                    wild_exploited_n = 1.0
                    flag_ms_cve_data_all = True
                    mentioned.append("<a href=\"https://msrc.microsoft.com/update-guide/vulnerability/" + cve +
                                     "\">Microsoft</a>")

    # Detecting false positives in wild exploitation

    if  flag_vulners_cisa == True and \
        flag_vulners_attackerkb == False and \
        flag_vulners_other == False and \
        flag_attackerkb == False and \
        flag_ms_cve_data_all == False:
        # If we have only a link to CISA, most likely CISA reports doesn't have direct 'Exploited in the wild' mention
        wild_exploited = False

    if  flag_vulners_cisa == True and \
        flag_vulners_attackerkb == False and \
        flag_vulners_other == False and \
        flag_attackerkb == False and \
        flag_ms_cve_data_all == False:
        # If we have an attackerkb object link in Vulners and don't have direct link to attackerkb, most likely it's
        # an error at Vulners (CISA object link doesn't matter)
        wild_exploited = False

    # flag_vulners_attackerkb = False
    # flag_vulners_cisa = False
    # flag_vulners_other = False
    # flag_attackerkb = False
    # flag_ms_cve_data_all = False

    if not wild_exploited:
        wild_exploited_n = 0
        wild_exploited_c = "Exploitation in the wild is NOT mentioned on Vulners, Microsoft and AttackerKB websites"
    else:
        if len(mentioned) == 1:
            wild_exploited_c = "Exploitation in the wild is mentioned on " + ", ".join(mentioned) + " website"
        else:
            wild_exploited_c = "Exploitation in the wild is mentioned on " + ", ".join(mentioned) + " websites"
    wild_exploited_k = 18

    ######## Product
    # Using the Product from combined_cve_data_all, that is from NVD or Microsoft
    vuln_product = "Unknown Product"
    vulnerable_product_is_common_n = 0
    vulnerable_product_is_common_c = "Unknown Product"
    if cve in cve_data_all['combined_cve_data_all']:
        vuln_product = cve_data_all['combined_cve_data_all'][cve]['vuln_product']
        if vuln_product != "Unknown Product":
            vulnerable_product_is_common_n = 0
            vulnerable_product_is_common_c = "Unclassified Product"

    product_data = profile['product_data']
    if vuln_product in product_data:
        vulnerable_product_is_common_n = product_data[vuln_product]['prevalence']
        vulnerable_product_is_common_c = vuln_product
        if "description" in product_data[vuln_product]:
            if product_data[vuln_product]["description"] != "":
                vulnerable_product_is_common_c = product_data[vuln_product]["description"]
    vulnerable_product_is_common_k = 14

    ######## Vulnerability type
    # Using the Vulnerability Type from combined_cve_data_all, that is from NVD or Microsoft
    vuln_type = cve_data_all['combined_cve_data_all'][cve]['vuln_type']
    if  vuln_type in data_classification_vulnerability_types.vulnerability_type_data:
        criticality_of_vulnerability_type_n = data_classification_vulnerability_types.vulnerability_type_data[vuln_type]['criticality']
    else:
        criticality_of_vulnerability_type_n = 0
    criticality_of_vulnerability_type_k = 15
    criticality_of_vulnerability_type_c = vuln_type

    ########

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
    vvs_struct['components']['EPSS Percentile'] = {
        'value': epss_score_n,
        'weight': epss_score_k,
        'comment': epss_score_c
    }
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

def get_cve_scores(all_cves, cve_data_all, profile):
    functions_tools.print_debug_message("Counting CVE scores...")
    scores_dict = dict()
    for cve in all_cves:
        scores_dict[cve] = get_vvs_struct_for_cve(cve, cve_data_all, profile)
    return(scores_dict)
