import credentials
import re
import json
import os
import data_ms_patch_tuesday
import data_vulnerability_classification
import functions_source_ms_cve
import functions_source_nvd_cve
import functions_profile_ms_patch_tuesday
import functions_source_vulners
import functions_tools

def get_vuln_products(ms_cve_data_all):
    all_vuln_products = set()
    for cve_id in ms_cve_data_all:
        if 'vuln_product' in ms_cve_data_all[cve_id]:
            all_vuln_products.add(ms_cve_data_all[cve_id]['vuln_product'])
        else:
            print("No vuln_product for item")
            print(ms_cve_data_all[cve_id])
            exit()

    all_vuln_products = list(all_vuln_products)
    all_vuln_products.sort()
    return all_vuln_products


def get_vuln_types(ms_cve_data_all):
    all_vuln_types = set()
    for cve_id in ms_cve_data_all:
        all_vuln_types.add(ms_cve_data_all[cve_id]['vuln_type'])
    all_vuln_types = list(all_vuln_types)
    all_vuln_types.sort()

    # add types in order of vulnerability_types_priority
    prioritized_vuln_types = list()
    for vuln_type in data_vulnerability_classification.vulnerability_types_priority:
        if vuln_type in all_vuln_types:
            prioritized_vuln_types.append(vuln_type)

    # add other types in alphabetical order
    for vuln_type in all_vuln_types:
        if vuln_type not in prioritized_vuln_types:
            prioritized_vuln_types.append(vuln_type)

    return prioritized_vuln_types


### Filters
def get_vulns_filtered_by_exploited(exploited, ms_cve_data):
    vulnerabilities = dict()
    for cve_id in ms_cve_data:
        if ms_cve_data[cve_id]['exploited'] == exploited:
            vulnerabilities[cve_id] = ms_cve_data[cve_id]
    return vulnerabilities


def get_vulns_filtered_by_exploitation_likeliness(exploitation_likeliness, ms_cve_data):
    vulnerabilities = dict()
    for cve_id in ms_cve_data:
        if ms_cve_data[cve_id]["exploitabilityAssessment"]["latestReleaseExploitability"][
            "name"] == exploitation_likeliness:
            vulnerabilities[cve_id] = ms_cve_data[cve_id]
        if ms_cve_data[cve_id]["exploitabilityAssessment"]["olderReleaseExploitability"][
            "name"] == exploitation_likeliness:
            vulnerabilities[cve_id] = ms_cve_data[cve_id]
    return (vulnerabilities)


def get_vulns_filtered_by_product(product, ms_cve_data):
    vulnerabilities = dict()
    for cve_id in ms_cve_data:
        if ms_cve_data[cve_id]['vuln_product'] == product:
            vulnerabilities[cve_id] = ms_cve_data[cve_id]
    return (vulnerabilities)


def get_vulns_filtered_by_type(type, ms_cve_data):
    vulnerabilities = dict()
    for cve_id in ms_cve_data:
        if ms_cve_data[cve_id]['vuln_type'] == type:
            vulnerabilities[cve_id] = ms_cve_data[cve_id]
    return (vulnerabilities)


def get_vulns_filtered_not_in_list(cve_ids, ms_cve_data):
    vulnerabilities = dict()
    for cve_id in ms_cve_data:
        if cve_id not in cve_ids:
            vulnerabilities[cve_id] = ms_cve_data[cve_id]
    return (vulnerabilities)


### Formating
def get_cve_line(cves):
    cves = list(cves)
    cves.sort()
    cve_line = ", ".join(cves)
    return (cve_line)


def get_cve_line_html(cves, cve_data):
    cves = list(cves)
    cves.sort()
    cve_html = set()
    for cve_id in cves:
        severity = cve_data[cve_id]['severity']
        color = ""
        if severity == "critical":
            color = "red"
        if severity == "important":
            color = "orange"
        if severity == "moderate":
            color = "#CCCC00" #yellow
        if severity == "low":
            color = "blue"
        if color != "":
            cve_html.add(
                '<a style="color:' + color + ';" href="https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/' + \
                cve_id + '">' + cve_id + "</a>")
        else:
            cve_html.add("<" + severity + ">" + cve_id + "</" + severity + ">")
    cve_html = list(cve_html)
    cve_html.sort()
    cve_line = ", ".join(cve_html)
    return (cve_line)


def get_vuln_type_html(type, config):
    vuln_icons_source = config['vuln_icons_source']
    html_img_tag = '<img style="vertical-align: middle; margin-right: 15px; margin-top: 2px; margin-bottom: 2px;" ' \
                   'width="32"  src=" '
    html_img_tag += vuln_icons_source
    html_img_tag += '/' + data_vulnerability_classification.type_to_icon[type] + '.png">' + type
    return html_img_tag


### Reports
def get_product_based_repot(current_cve_data, min_cve_number, report_config, source):
    processed_cves = set()
    report_txt = ""
    report_html = ""
    all_products = get_vuln_products(current_cve_data)
    for product in all_products:
        product_cves = get_vulns_filtered_by_product(product, current_cve_data)
        number_of_cves = len(product_cves)
        if number_of_cves > min_cve_number:
            report_txt += product + "\n"
            report_html += "<h4>" + product + "</h4>" + "\n"
            report_html += "<ul>" + "\n"
            for type in get_vuln_types(product_cves):
                cves_by_type = get_vulns_filtered_by_type(type, product_cves)
                report_txt += " - " + type + " (" + get_cve_line(cves_by_type.keys()) + ")" + "\n"
                report_html += "<li>" + get_vuln_type_html(type, report_config) + " (" + get_cve_line_html(
                    cves_by_type.keys(), current_cve_data) + ")" + "</li>" + "\n"
                report_html += get_comments_for_cves(source, cves_by_type)["report_html"]
            report_html += "</ul>" + "\n"
            for cve in product_cves.keys():
                processed_cves.add(cve)
    return {"report_txt": report_txt, "report_html": report_html, "processed_cves": processed_cves}


def get_type_based_repot(current_cve_data, report_config, source):
    processed_cves = set()
    report_txt = ""
    report_html = ""
    all_types = get_vuln_types(current_cve_data)
    for type in all_types:
        type_cves = get_vulns_filtered_by_type(type, current_cve_data)
        report_txt += type + "\n"
        report_html += "<h4>" + get_vuln_type_html(type, report_config) + "</h4>" + "\n"
        report_html += "<ul>" + "\n"
        for product in get_vuln_products(type_cves):
            cves_by_product = get_vulns_filtered_by_product(product, type_cves)
            report_txt += " - " + product + " (" + get_cve_line(cves_by_product.keys()) + ")" + "\n"
            report_html += "<li>" + product + " (" + get_cve_line_html(cves_by_product.keys(),
                                                                       current_cve_data) + ")" + "</li>" + "\n"
            report_html += get_comments_for_cves(source, cves_by_product)["report_html"]
        report_html += "</ul>" + "\n"
        for cve in type_cves.keys():
            processed_cves.add(cve)
    return {"report_txt": report_txt, "report_html": report_html, "processed_cves": processed_cves}

def get_components_list_sorted(cve_scores):
    cve_id = list(cve_scores.keys())[0]
    component_dict = dict()
    for component in cve_scores[cve_id]['components']:
        component_dict[component] = cve_scores[cve_id]['components'][component]['weight']
    components = functions_tools.get_sorted_list_from_weighted_dict(component_dict)
    # for component in components:
    #     print(component + ";" + str(component_dict[component]))
    return(components)

def get_vulristics_score_report(cve_scores, ms_cve_data):
    report_txt = ""
    report_html = ""

    cve_score_dict = dict()
    for cve in cve_scores:
        cve_score_dict[cve] = int(cve_scores[cve]['value']*1000)
    sorted_cves = functions_tools.get_sorted_list_from_weighted_dict(cve_score_dict)

    components = get_components_list_sorted(cve_scores)

    for cve in sorted_cves:
        report_txt += cve + "\n"
        report_html += "<p>" + str(int(cve_scores[cve]['value']*1000)) + " - " + cve + \
                       " - " + str(ms_cve_data[cve]['vuln_type']) + \
                       " - " + str(ms_cve_data[cve]['vuln_product'])  + \
                       "</br>"
        #report_html +=  str(cve_scores[cve])
        report_html += "<table>"
        for component in components:
            report_html += "<tr>" + \
                            "<td>" + component  + "</td>" +\
                           "<td>" + str(cve_scores[cve]['components'][component]['value']) + "</td>" + \
                           "<td>" + str(cve_scores[cve]['components'][component]['weight']) + "</td>" + \
                           "</tr>"
        report_html += "</table>"
        report_html += "</p>\n"

    # report_txt = str(cve_scores)
    # report_html = str(cve_scores)
    return {"report_txt": report_txt, "report_html": report_html}

def get_statics_report(ms_cve_data_all):
    report_txt = ""
    report_html = ""

    all_vulnerabilities = set()
    for vulnerability in ms_cve_data_all:
        all_vulnerabilities.add(vulnerability)

    critical_vulnerability = set()
    for vulnerability in ms_cve_data_all:
        if ms_cve_data_all[vulnerability]['severity'] == "critical":
            critical_vulnerability.add(vulnerability)

    important_vulnerability = set()
    for vulnerability in ms_cve_data_all:
        if ms_cve_data_all[vulnerability]['severity'] == "important":
            important_vulnerability.add(vulnerability)

    moderate_vulnerability = set()
    for vulnerability in ms_cve_data_all:
        if ms_cve_data_all[vulnerability]['severity'] == "moderate":
            moderate_vulnerability.add(vulnerability)

    low_vulnerability = set()
    for vulnerability in ms_cve_data_all:
        if ms_cve_data_all[vulnerability]['severity'] == "low":
            low_vulnerability.add(vulnerability)

    report_txt += "All vulnerabilities: " + str(len(all_vulnerabilities)) + "\n"
    report_txt += "Critical: " + str(len(critical_vulnerability)) + "\n"
    report_txt += "Important: " + str(len(important_vulnerability)) + "\n"
    report_txt += "Moderate: " + str(len(moderate_vulnerability)) + "\n"
    report_txt += "Low: " + str(len(low_vulnerability)) + "\n"

    report_html += "<ul>" + "\n"
    report_html += "<li>" + "All vulnerabilities: " + str(len(all_vulnerabilities)) + "</li>" + "\n"
    report_html += "<li>" + "Critical: " + str(len(critical_vulnerability)) + "</li>" + "\n"
    report_html += "<li>" + "Important: " + str(len(important_vulnerability)) + "</li>" + "\n"
    report_html += "<li>" + "Moderate: " + str(len(moderate_vulnerability)) + "</li>" + "\n"
    report_html += "<li>" + "Low: " + str(len(low_vulnerability)) + "</li>" + "\n"
    report_html += "</ul>" + "\n"

    return {"report_txt": report_txt, "report_html": report_html}


def get_comments_for_cves(source, processed_cves):
    report_html = ""
    if 'comments' in source:
        comments = source['comments']
        for comment_id in comments:
            for line in comments[comment_id].split("\n"):
                print_line = False
                for cve in processed_cves:
                    if cve in line:
                        print_line = True
                if print_line:
                    for cve in processed_cves:
                        line = re.sub(cve, "<b>" + cve + "</b>", line)
                    report_html += "<p>" + comment_id + ": " + line + "</p>" + "\n"

    return {"report_html": report_html}


def make_pt_report_for_profile(cve_data_all, cve_scores, report_config, source):
    ms_cve_data = cve_data_all['ms_cve_data_all']

    if report_config['ignore_comments']:
        source['comments'] = {}

    f = open("report/template.html", "r")
    template = f.read()
    f.close()
    html_content = "<h1>" + source['report_name'] + "</h1>"

    report_data = get_statics_report(ms_cve_data)
    name = "Basic MS Vulnerabilities Scores Statistics"
    print("== " + name + " ==")
    html_content += "<h3>" + name + "</h3>" + "\n"
    print(report_data['report_txt'])
    html_content += report_data['report_html']

    report_data = get_vulristcs_score_report(cve_scores, ms_cve_data)
    name = "Vulristics Vulnerability Scores"
    print("== " + name + " ==")
    html_content += "<h3>" + name + "</h3>" + "\n"
    print(report_data['report_txt'])
    html_content += report_data['report_html']

    current_cve_data = ms_cve_data
    exploited_cves = get_vulns_filtered_by_exploited("Yes", current_cve_data)
    report_data = get_type_based_repot(exploited_cves, report_config, source)
    name = "Exploitation detected"
    print("== " + name + " (" + str(len(report_data['processed_cves'])) + ") ==")
    html_content += "<h3>" + name + " (" + str(len(report_data['processed_cves'])) + ")</h3>" + "\n"
    print(report_data['report_txt'])
    html_content += report_data['report_html']
    # html_content += get_comments_for_cves(source, report_data['processed_cves'])["report_html"]
    current_cve_data = get_vulns_filtered_not_in_list(report_data['processed_cves'], current_cve_data)


    # exploitation_more_likely = get_vulns_filtered_by_exploitation_likeliness("Exploitation More Likely",
    #                                                                          current_cve_data)
    # report_data = get_type_based_repot(exploitation_more_likely, report_config, source)
    # name = "Exploitation more likely"
    # print("== " + name + " (" + str(len(report_data['processed_cves'])) + ") ==")
    # html_content += "<h3>" + name + " (" + str(len(report_data['processed_cves'])) + ")</h3>" + "\n"
    # print(report_data['report_txt'])
    # html_content += report_data['report_html']
    # # html_content += get_comments_for_cves(source, report_data['processed_cves'])["report_html"]
    # current_cve_data = get_vulns_filtered_not_in_list(report_data['processed_cves'], current_cve_data)

    # report_data = get_product_based_repot(current_cve_data, min_cve_number=5, report_config=report_config,
    #                                       source=source)
    # name = "Other Product based"
    # print("== " + name + " (" + str(len(report_data['processed_cves'])) + ") ==")
    # html_content += "<h3>" + name + " (" + str(len(report_data['processed_cves'])) + ")</h3>" + "\n"
    # print(report_data['report_txt'])
    # html_content += report_data['report_html']
    # # html_content += get_comments_for_cves(source, report_data['processed_cves'])["report_html"]
    # current_cve_data = get_vulns_filtered_not_in_list(report_data['processed_cves'], current_cve_data)

    report_data = get_type_based_repot(current_cve_data, report_config, source)
    name = "Other Vulnerability Type based"
    print("== " + name + " (" + str(len(report_data['processed_cves'])) + ") ==")
    html_content += "<h3>" + name + " (" + str(len(report_data['processed_cves'])) + ")</h3>" + "\n"
    print(report_data['report_txt'])
    html_content += report_data['report_html']
    # html_content += get_comments_for_cves(source, report_data['processed_cves'])["report_html"]
    current_cve_data = get_vulns_filtered_not_in_list(report_data['processed_cves'], current_cve_data)

    html_content = re.sub("##Content##", html_content, template)

    f = open("report/" + source['file_name_prefix'] + "_" + report_config['file_name_suffix'] + ".html", "w")
    f.write(html_content)
    f.close()

def get_cve_scores(all_cves,cve_data_all,profile):
    scores_dict = dict()
    for cve in all_cves:

        ######## NVD CVSS

        # print(json.dumps(cve_data_all['nvd_cve_data_all'][cve], indent=4))
        # print(cve_data_all['nvd_cve_data_all'][cve]['result']['CVE_Items'][0]['impact']['baseMetricV3']['cvssV3'])
        cvss_base_score = cve_data_all['nvd_cve_data_all'][cve]['result']['CVE_Items'][0]['impact']['baseMetricV3']['cvssV3']['baseScore']
        cvss_base_score_n = int(cvss_base_score)/10
        cvss_base_score_k = 9
        cvss_attack_is_network = cve_data_all['nvd_cve_data_all'][cve]['result']['CVE_Items'][0]['impact']['baseMetricV3']['cvssV3']['attackVector']
        if cvss_attack_is_network == "NETWORK":
            cvss_attack_is_network_n = 1
        else:
            cvss_attack_is_network_n = 0
        cvss_attack_is_network_k = 10
        cvss_attack_ease = cve_data_all['nvd_cve_data_all'][cve]['result']['CVE_Items'][0]['impact']['baseMetricV3']['cvssV3']['attackComplexity']
        if cvss_attack_ease == "LOW":
            cvss_attack_ease_n = 1
        else:
            cvss_attack_ease_n = 0.2
        cvss_attack_ease_k = 5
        cvss_exploitability_score = cve_data_all['nvd_cve_data_all'][cve]['result']['CVE_Items'][0]['impact']['baseMetricV3']['exploitabilityScore']
        cvss_exploitability_score_n = int(cvss_exploitability_score) / 10
        cvss_exploitability_score_k = 5
        cvss_impact_score = cve_data_all['nvd_cve_data_all'][cve]['result']['CVE_Items'][0]['impact']['baseMetricV3']['impactScore']
        cvss_impact_score_n = int(cvss_impact_score) / 10
        cvss_impact_score_k = 3

        ######## Mentioned by vendors
        all_vendors_in_report = len(profile['comments'].keys())
        mentioned = 0
        for vendor in profile['comments']:
            if cve in profile['comments'][vendor]:
                mentioned += 1
        mentioned_by_vm_vendor_n = mentioned / all_vendors_in_report
        mentioned_by_vm_vendor_k = 20

        ######## Exploit
        # Currently works only with Vulners data
        is_public_exploit = cve_data_all['vulners_cve_data_all'][cve]['public_exploit']
        if is_public_exploit:
            public_exploit_exists_n = 1
        else:
            public_exploit_exists_n = 0
        public_exploit_exists_k = 25

        ######## Product
        # Currently works only with Microsoft data
        vuln_product = cve_data_all['ms_cve_data_all'][cve]['vuln_product']
        vulnerable_product_is_common_n = 0.3
        if "Windows" in vuln_product: #Some standard Windows component
            vulnerable_product_is_common_n = 1
        elif "DNS" in vuln_product or "RDP" in vuln_product:
            vulnerable_product_is_common_n = 0.9
        elif "Office" in vuln_product or "Word" in vuln_product or "Excel" in vuln_product or "Outlook" in vuln_product:
            vulnerable_product_is_common_n = 0.7
        elif "SharePoint" in vuln_product:
            vulnerable_product_is_common_n = 0.6
        vulnerable_product_is_common_k = 12

        ######## Vulnerability type
        # Currently works only with Microsoft data
        #print(json.dumps(cve_data_all['ms_cve_data_all'][cve]))
        vuln_type = cve_data_all['ms_cve_data_all'][cve]['vuln_type']
        criticality_of_vulnerability_type_n = data_vulnerability_classification.type_to_criticality[vuln_type]
        criticality_of_vulnerability_type_k = 15

        scores_dict[cve] =  { 'components':
                      {
                          'cvss_base_score': {
                              'value': cvss_base_score_n,
                              'weight': cvss_base_score_k
                          },
                          'cvss_attack_is_network': {
                              'value': cvss_attack_is_network_n,
                              'weight': cvss_attack_is_network_k
                          },
                          'cvss_attack_ease': {
                              'value': cvss_attack_ease_n,
                              'weight': cvss_attack_ease_k
                          },
                          'cvss_exploitability_score': {
                              'value': cvss_exploitability_score_n,
                              'weight': cvss_exploitability_score_k
                          },
                          'cvss_impact_score': {
                              'value': cvss_impact_score_n,
                              'weight': cvss_impact_score_k
                          },
                          'criticality_of_vulnerability_type': {
                              'value': criticality_of_vulnerability_type_n,
                              'weight': criticality_of_vulnerability_type_k
                          },
                          'mentioned_by_vm_vendor': {
                              'value': mentioned_by_vm_vendor_n,
                              'weight': mentioned_by_vm_vendor_k
                          },
                          'vulnerable_product_is_common': {
                              'value': vulnerable_product_is_common_n,
                              'weight': vulnerable_product_is_common_k
                          },
                          'public_exploit_exists': {
                              'value': public_exploit_exists_n,
                              'weight': public_exploit_exists_k
                          },
                      }

                  }
        score_value = 0
        for component in scores_dict[cve]['components']:
            score_value += scores_dict[cve]['components'][component]['value'] * scores_dict[cve]['components'][component]['weight']
        all_weights = 0
        for component in scores_dict[cve]['components']:
            all_weights  += scores_dict[cve]['components'][component]['weight']
        score_value = score_value/all_weights
        scores_dict[cve]['value'] = score_value

    return(scores_dict)

def make_ms_patch_tuesday_reports(month, year, patch_tuesday_date, rewrite_flag=False):
    # month = "October"
    # year = "2020"
    # patch_tuesday_date = "10/13/2020"

    source_id = month + " " + year
    file_name = month.lower() + year + ".json"

    if not os.path.isfile("data/profile_ms_patch_tuesday/" + file_name):
        functions_profile_ms_patch_tuesday.create_profile(month, year, patch_tuesday_date)

    f = open("data/profile_ms_patch_tuesday/" + file_name, "r")
    patch_tuesday_profiles = json.loads(f.read())
    f.close()

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

    ms_cve_data_all = dict()
    for cve_id in all_cves:
        ms_cve_data = functions_source_ms_cve.get_ms_cve_data(cve_id, rewrite_flag)
        if not ms_cve_data['not_found_error']:
            ms_cve_data_all[cve_id] = ms_cve_data

    nvd_cve_data_all = dict()
    for cve_id in all_cves:
        nvd_cve_data = functions_source_nvd_cve.get_nvd_cve_data(cve_id, rewrite_flag)
        nvd_cve_data_all[cve_id] =  nvd_cve_data

    vulners_cve_data_all = dict()
    if credentials.vulners_key != "": # If we  have Vulners API key
        for cve_id in all_cves:
            vulners_cve_data = functions_source_vulners.get_vulners_data(cve_id, rewrite_flag)
            vulners_cve_data_all[cve_id] = vulners_cve_data

    cve_data_all = {'ms_cve_data_all':ms_cve_data_all,
                    'nvd_cve_data_all':nvd_cve_data_all,
                    'vulners_cve_data_all': vulners_cve_data_all}

    cve_scores = get_cve_scores(all_cves, cve_data_all, patch_tuesday_profiles[source_id])
    # print(json.dumps(cve_scores, indent=4))

    for report_config_name in data_ms_patch_tuesday.patch_tuesday_report_configs:
        make_pt_report_for_profile(cve_data_all, cve_scores,
                                     data_ms_patch_tuesday.patch_tuesday_report_configs[report_config_name],
                                     patch_tuesday_profiles[source_id])