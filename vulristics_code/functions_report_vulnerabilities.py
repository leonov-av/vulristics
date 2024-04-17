from vulristics_code import functions_combined_vulnerability_data, data_classification_products, functions_score, functions_tools, \
    data_report_configs, data_classification_vulnerability_types
import re
import json
import copy
from datetime import datetime


def get_vuln_products(ms_cve_data_all):
    # Getting vulnerable products for CVE items
    all_vuln_products = set()
    for cve_id in ms_cve_data_all:
        if 'vuln_product' in ms_cve_data_all[cve_id]:
            all_vuln_products.add(ms_cve_data_all[cve_id]['vuln_product'])
        else:
            print("No vuln_product for item")
            print(ms_cve_data_all[cve_id])
    all_vuln_products = list(all_vuln_products)
    all_vuln_products.sort()
    return all_vuln_products


def get_vulnerability_types_priority(vulnerability_type_data):
    vulnerability_types_priority = list()
    criticalities = dict()
    for vuln_type in vulnerability_type_data:
        if not vulnerability_type_data[vuln_type]['criticality'] in criticalities:
            criticalities[vulnerability_type_data[vuln_type]['criticality']] = list()
        criticalities[vulnerability_type_data[vuln_type]['criticality']].append(vuln_type)
    criticality_keys = list(criticalities.keys())
    criticality_keys.sort(reverse=True)
    for criticality_key in criticality_keys:
        vuln_types = criticalities[criticality_key]
        vuln_types.sort()
        for vuln_type in vuln_types:
            vulnerability_types_priority.append(vuln_type)
    return vulnerability_types_priority


def get_vuln_types(ms_cve_data_all):
    # Getting vulnerability types for CVE items
    all_vuln_types = set()
    for cve_id in ms_cve_data_all:
        all_vuln_types.add(ms_cve_data_all[cve_id]['vuln_type'])
    all_vuln_types = list(all_vuln_types)
    all_vuln_types.sort()
    # Add types in order of vulnerability_types_priority
    prioritized_vuln_types = list()
    for vuln_type in get_vulnerability_types_priority(data_classification_vulnerability_types.vulnerability_type_data):
        if vuln_type in all_vuln_types:
            prioritized_vuln_types.append(vuln_type)
    # Add other types in alphabetical order
    for vuln_type in all_vuln_types:
        if vuln_type not in prioritized_vuln_types:
            prioritized_vuln_types.append(vuln_type)
    return prioritized_vuln_types


def get_vulns_filtered_by_wild_exploited(exploited, current_cve_data, cve_scores):
    vulnerabilities = dict()
    for cve_id in current_cve_data:
        wild_exploited = False
        if cve_scores[cve_id]['components']['Exploited in the Wild']['value'] == 1:
            wild_exploited = True
        if wild_exploited == True and exploited == "Yes":
            vulnerabilities[cve_id] = current_cve_data[cve_id]
        elif wild_exploited == False and exploited == "No":
            vulnerabilities[cve_id] = current_cve_data[cve_id]
    return vulnerabilities


def get_vulns_filtered_by_public_exploit_exists(public_exploit_exists, current_cve_data, cve_scores):
    vulnerabilities = dict()
    for cve_id in current_cve_data:
        exploit_found = False
        if cve_scores[cve_id]['components']['Public Exploit Exists']['value'] == 1:
            exploit_found = True
        if exploit_found == True and public_exploit_exists == "Yes":
            vulnerabilities[cve_id] = current_cve_data[cve_id]
        elif exploit_found == False and public_exploit_exists == "No":
            vulnerabilities[cve_id] = current_cve_data[cve_id]
    return vulnerabilities


def get_vulns_filtered_by_exploitation_likeliness(exploitation_likeliness, ms_cve_data):
    # Getting Exploitation is likely vulnerabilities (based on MS data)
    vulnerabilities = dict()
    for cve_id in ms_cve_data:
        latest_rel_expl = ms_cve_data[cve_id]["exploitabilityAssessment"]["latestReleaseExploitability"]["name"]
        if latest_rel_expl == exploitation_likeliness:
            vulnerabilities[cve_id] = ms_cve_data[cve_id]
        older_rel_expl = ms_cve_data[cve_id]["exploitabilityAssessment"]["olderReleaseExploitability"]["name"]
        if older_rel_expl == exploitation_likeliness:
            vulnerabilities[cve_id] = ms_cve_data[cve_id]
    return vulnerabilities


def get_vulns_filtered_by_product(product, cve_data):
    vulnerabilities = dict()
    for cve_id in cve_data:
        if cve_data[cve_id]['vuln_product'] == product:
            vulnerabilities[cve_id] = cve_data[cve_id]
    return vulnerabilities


def get_vulns_filtered_by_type(vuln_type, cve_data):
    vulnerabilities = dict()
    for cve_id in cve_data:
        if cve_data[cve_id]['vuln_type'] == vuln_type:
            vulnerabilities[cve_id] = cve_data[cve_id]
    return vulnerabilities


def get_vulns_filtered_not_in_list(cve_ids, cve_data):
    vulnerabilities = dict()
    for cve_id in cve_data:
        if cve_id not in cve_ids:
            vulnerabilities[cve_id] = cve_data[cve_id]
    return vulnerabilities


### Formating
def get_cve_line(cves):
    # CVE list to string
    cves = list(cves)
    cves.sort()
    cve_line = ", ".join(cves)
    return cve_line


def get_colored_text(color, text, c_type="text", params=None):
    # Make colored HTML text or links
    if color == "":
        color = "default"
    class_name = color.lower()
    if c_type == "text":
        result = "<span class=\"" + class_name + "\">" + text + "</span>"
    elif c_type == "link":
        result = "<a class=\"" + class_name + "\" href=\"" + params['url'] + "\">" + text + "</a>"
    return result


def get_ms_cve_line_html_vss(cve, cve_scores):
    #params = {'url': 'https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/' + cve}
    if "BDU" in cve:
        params = {'url': 'https://bdu.fstec.ru/vul/' + re.sub("BDU:","",cve)}
    else:
        params = {'url': 'https://vulners.com/cve/' + cve}

    return (get_colored_text(color=cve_scores[cve]['level'],
                             text=cve,
                             c_type="link",
                             params=params))


def get_ms_cve_lines_html_vss(cves, cve_scores):
    # Make colored HTML MS CVE links based on VVS
    cves = list(cves)
    cves.sort()
    cve_html = list()
    for cve_id in cves:
        cve_html.append(get_ms_cve_line_html_vss(cve_id, cve_scores))
    cve_line = ", ".join(cve_html)
    return cve_line


def get_vuln_type_icon_html(type, config):
    vuln_icons_source = config['vuln_icons_source']
    icon = data_classification_vulnerability_types.vulnerability_type_data[type]['icon']
    img_src = vuln_icons_source + '/' +  icon + '.png'
    html_img_tag = '<img class="vulnerability_type" src="' + img_src + '">'
    return html_img_tag


def get_vuln_type_html(type, config):
    html_img_tag = get_vuln_type_icon_html(type, config) + type
    return html_img_tag


### Reports
def get_product_based_report(current_cve_data, min_cve_number, report_config, source, cve_scores):
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
                report_html += "<li>" + get_vuln_type_html(type, report_config) + " (" + get_ms_cve_lines_html_vss(
                    cves_by_type.keys(), cve_scores) + ")" + "</li>" + "\n"
                report_html += get_comments_for_cves(source, cves_by_type)["report_html"]
            report_html += "</ul>" + "\n"
            for cve in product_cves.keys():
                processed_cves.add(cve)
    return {"report_txt": report_txt, "report_html": report_html, "processed_cves": processed_cves}


def get_type_based_report(current_cve_data, report_config, source, cve_scores):
    # Make a reports by grouping vulnerabilitites by product and vulnerability vuln_type
    processed_cves = set()
    report_txt = ""
    report_html = ""
    all_types = get_vuln_types(current_cve_data)  # all vulnerability types
    report_dict = dict()
    for vuln_type in all_types:
        report_dict[vuln_type] = dict()
        report_dict[vuln_type]['score'] = 0
        report_dict[vuln_type]['products'] = dict()
        type_cves = get_vulns_filtered_by_type(vuln_type, current_cve_data)
        for product in get_vuln_products(type_cves):
            report_dict[vuln_type]['products'][product] = dict()
            report_dict[vuln_type]['products'][product]['score'] = 0
            report_dict[vuln_type]['products'][product]['cves'] = dict()
            cves_by_product = get_vulns_filtered_by_product(product, type_cves)
            for cve in cves_by_product:
                report_dict[vuln_type]['products'][product]['cves'][cve] = dict()
                report_dict[vuln_type]['products'][product]['cves'][cve]['score'] = cve_scores[cve]
        for cve in type_cves.keys():
            processed_cves.add(cve)
    # Adding max VVS of vulnerabilities as a score for product
    for vuln_type in report_dict:
        for product in report_dict[vuln_type]['products']:
            all_scores = list()
            for cve in report_dict[vuln_type]['products'][product]['cves']:
                all_scores.append(report_dict[vuln_type]['products'][product]['cves'][cve]['score']['value'])
            report_dict[vuln_type]['products'][product]['score'] = max(all_scores)
    # Adding max VVS of products as a score for vulnerability type
    for vuln_type in report_dict:
        all_scores = list()
        for product in report_dict[vuln_type]['products']:
            all_scores.append(report_dict[vuln_type]['products'][product]['score'])
        report_dict[vuln_type]['score'] = max(all_scores)

    def get_cve_for_vuln_type(vuln_type_data):
        all_cves = list()
        for product in vuln_type_data['products']:
            for cve in vuln_type_data['products'][product]['cves']:
                all_cves.append(cve)
        return all_cves

    # Making sorted list of vulnerability types
    vuln_types_dict = dict()
    for vuln_type in report_dict:
        vuln_types_dict[vuln_type] = report_dict[vuln_type]['score']
    sorted_list_of_vulnerability_types = functions_tools.get_sorted_list_from_weighted_dict(vuln_types_dict)
    for vuln_type in sorted_list_of_vulnerability_types:
        report_txt += vuln_type + "\n"
        report_html += "<h4>" + get_vuln_type_html(vuln_type, report_config) + " (" + str(
            len(get_cve_for_vuln_type(report_dict[vuln_type]))) + ")</h4>" + "\n"
        report_html += "<ul>" + "\n"
        # Making sorted list of products
        product_dict = dict()
        for product in report_dict[vuln_type]['products']:
            product_dict[product] = report_dict[vuln_type]['products'][product]['score']
        sorted_list_of_products = functions_tools.get_sorted_list_from_weighted_dict(product_dict)
        for product in sorted_list_of_products:
            cves = report_dict[vuln_type]['products'][product]['cves'].keys()
            cves = list(cves)
            cves.sort()
            report_txt += " - " + product + " (" + get_cve_line(cves) + ")" + "\n"
            report_html += "<li>" + product + " (" + get_ms_cve_lines_html_vss(cves, cve_scores) + ")" + "</li>" + "\n"
            report_html += get_comments_for_cves(source, cves)["report_html"]
        report_html += "</ul>" + "\n"

    return {"report_txt": report_txt, "report_html": report_html, "report_dict": report_dict,
            "processed_cves": processed_cves}


def get_components_list_sorted(cve_scores):
    if len(cve_scores) == 0: # fix for empty list
        return list()
    cve_id = list(cve_scores.keys())[0]
    component_dict = dict()
    for component in cve_scores[cve_id]['components']:
        component_dict[component] = cve_scores[cve_id]['components'][component]['weight']
    components = functions_tools.get_sorted_list_from_weighted_dict(component_dict)
    # for component in components:
    #     print(component + ";" + str(component_dict[component]))
    return components


def get_statistics(cve_scores):
    statistics = {
        "Urgent": set(),
        "Critical": set(),
        "High": set(),
        "Medium": set(),
        "Low": set(),
        "All vulnerabilities": set()
    }
    for cve in cve_scores:
        statistics[cve_scores[cve]['level']].add(cve)
        statistics["All vulnerabilities"].add(cve)
    return statistics


def get_vulristics_score_vulner_block(cve_scores, combined_cve_data_all, config, components, source, cve, n):

    report_html = ""
    report_html += "<p>" + get_colored_text("red", str(n) + ". ") + get_vuln_type_icon_html(
        combined_cve_data_all[cve]['vuln_type'], config) + \
                   " <b>" + str(combined_cve_data_all[cve]['vuln_type']) + \
                   "</b> - " + str(combined_cve_data_all[cve]['vuln_product']) + \
                   " (" + get_ms_cve_line_html_vss(cve, cve_scores) + ")" + \
                   " - " + get_colored_text(cve_scores[cve]['level'], cve_scores[cve]['level'] + " [" + str(
        int(cve_scores[cve]['value'] * 1000)) + "] ") + \
                   "</br>"

    report_html += "<p><b>Description:</b> " + combined_cve_data_all[cve]['description']  + "</p>"

    report_html += "<table class=\"vvs_table\">" \
                   "<tr class=\"vvs_table\">" \
                        "<th class=\"vvs_table\">Component</th>" \
                        "<th class=\"vvs_table\">Value</th>" \
                        "<th class=\"vvs_table\">Weight</th>" \
                        "<th class=\"vvs_table\">Comment</th>" \
                   "</tr>"
    for component in components:
        report_html += "<tr class=\"vvs_table\">" + \
                       "<td class=\"vvs_table\"><nowrap>" + component + "</nowrap></td>" + \
                       "<td class=\"vvs_table\">" + get_colored_text(cve_scores[cve]['components'][component]['level'],
                                                            str(cve_scores[cve]['components'][component]['value'])) \
                       + "</td>" + \
                       "<td class=\"vvs_table\">" + str(cve_scores[cve]['components'][component]['weight']) + "</td>" +\
                       "<td class=\"vvs_table\">" + get_colored_text(cve_scores[cve]['components'][component]['level'],
                                                    str(cve_scores[cve]['components'][component]['comment'])) \
                       + "</td>" + \
                       "</tr>"
    report_html += "</table>"
    comments = get_comments_for_cves(source, [cve])
    report_html += comments['report_html']
    report_html += "</p>\n"

    report_dict = {
        'vuln_id': cve,
        'vuln_type': str(combined_cve_data_all[cve]['vuln_type']),
        'vuln_product': str(combined_cve_data_all[cve]['vuln_product']),
        'level': cve_scores[cve]['level'],
        'vvs': int(cve_scores[cve]['value'] * 1000),
        'components': cve_scores[cve]['components'],
        'description': combined_cve_data_all[cve]['description'],
        'comments': comments['report_list']
    }

    return {"report_html": report_html, "report_dict":report_dict}


def get_vvs_statistics_report(cve_scores):
    report_txt = ""
    report_html = ""

    statistics = get_statistics(cve_scores)

    cve_score_dict = dict()
    for cve in cve_scores:
        cve_score_dict[cve] = int(cve_scores[cve]['value'] * 1000)

    criticalities = ["Urgent", "Critical", "High", "Medium", "Low"]
    report_html += "<ul>"
    report_html += "<li>" + "All vulnerabilities" + ': ' + str(len(statistics["All vulnerabilities"])) + "</li>"
    for criticality in criticalities:
        report_html += "<li>" + get_colored_text(criticality, criticality) + ': ' + str(
            len(statistics[criticality])) + "</li>"
    report_html += "</ul>"

    return {"report_txt": report_txt, "report_html": report_html}


def get_vulristics_score_report(combined_cve_data_all, cve_scores, config, source):
    report_txt = ""
    report_html = ""
    report_list = list()
    statistics = get_statistics(cve_scores)

    cve_score_dict = dict()
    for cve in cve_scores:
        cve_score_dict[cve] = int(cve_scores[cve]['value'] * 1000)
    sorted_cves = functions_tools.get_sorted_list_from_weighted_dict(cve_score_dict,
                                                                     combined_cve_data_all = combined_cve_data_all)

    criticalities = ["Urgent", "Critical", "High", "Medium", "Low"]
    components = get_components_list_sorted(cve_scores)

    n = 1
    for criticality in criticalities:
        report_html += "<h4>" + criticality + " (" + str(len(statistics[criticality])) + ")</h4>"
        for cve in sorted_cves:
            if cve in statistics[criticality] and cve in combined_cve_data_all:
                vulristics_score_vulner_block = get_vulristics_score_vulner_block(cve_scores, combined_cve_data_all, config, components,
                                                                 source, cve, n)
                report_html += vulristics_score_vulner_block['report_html']
                report_list.append(vulristics_score_vulner_block['report_dict'])

                n += 1

    return {"report_txt": report_txt, "report_html": report_html, 'report_list':report_list }


def get_sorted_product_name_list(product_data):
    value_to_products = dict()
    for product_name in product_data:
        if not product_data[product_name]['value'] in value_to_products:
            value_to_products[product_data[product_name]['value']] = list()
        value_to_products[product_data[product_name]['value']].append(product_name)
    values = list(value_to_products.keys())
    product_names = list()
    values.sort(reverse=True)
    for value in values:
        value_to_products[value].sort()
        for product_name in value_to_products[value]:
            product_names.append(product_name)
    return product_names


def get_cves_count_value_products_table(criticality, product_data, product_name):
    n = len(product_data[product_name]['cves'][criticality])
    if n == 0:
        return ""
    else:
        return get_colored_text(color=criticality, text=str(n), c_type="text", params=None)

def get_cves_count_value_comments_table(criticality, vulnerability_comment_data, comment_source):
    n = len(vulnerability_comment_data[comment_source]['cves'][criticality])
    if n == 0:
        return ""
    else:
        return get_colored_text(color=criticality, text=str(n), c_type="text", params=None)


def get_products_report(combined_cve_data_all, cve_scores, report_config, profile_data):
    report_txt = ""
    report_html = ""
    report_dict = dict()
    criticalities = ["Urgent", "Critical", "High", "Medium", "Low", "All"]
    product_data = dict()
    for cve in combined_cve_data_all:
        product_name = combined_cve_data_all[cve]['vuln_product']
        value = cve_scores[cve]['components']['Vulnerable Product is Common']['value']
        comment = cve_scores[cve]['components']['Vulnerable Product is Common']['comment']
        cve_level = cve_scores[cve]['level']
        if not product_name in product_data:
            product_data[product_name] = dict()
            product_data[product_name]['cves'] = dict()
            product_data[product_name]['value'] = value
            product_data[product_name]['comment'] = comment
            for crit in criticalities:
                product_data[product_name]['cves'][crit] = list()
        product_data[product_name]['cves'][cve_level].append(cve)
        product_data[product_name]['cves']['All'].append(cve)
        product_data[product_name]['data'] = combined_cve_data_all[cve]['product_data']


    report_html = "<p><table class=\"product_table\">"
    report_html += "<tr class=\"product_table\">"
    report_html += "<th class=\"product_table\">" + "Product Name" + "</th>"
    report_html += "<th class=\"product_table\">" + "Prevalence" + "</th>"
    for criticality in ['Urgent', 'Critical', 'High', 'Medium', 'Low', 'All']:
        text = get_colored_text(color=criticality, text= criticality[0][0], c_type="text", params=None)
        report_html += "<th class=\"product_table\">" + text + "</th>"
    report_html += "<th class=\"product_table\">" + "Comment" + "</th>"
    report_html += "</tr>\n"
    sorted_product_name_list = get_sorted_product_name_list(product_data)
    for product_name in sorted_product_name_list:
        report_html += "<tr class=\"product_table\">"
        report_html += "<td class=\"product_table\">" + product_name + "</td>"
        text = str(product_data[product_name]['value'])
        if text == "0":
            text = get_colored_text(color="Error", text=text, c_type="text", params=None)
        report_html += "<td class=\"product_table\">" + text + "</td>"
        for criticality in ['Urgent', 'Critical', 'High', 'Medium', 'Low', 'All']:
            text = get_cves_count_value_products_table(criticality, product_data, product_name)
            report_html += "<td class=\"product_table\">" + text + "</td>"
        text = product_data[product_name]['comment']
        if text == "Unclassified Product" or text == "Unknown Product":
            text = get_colored_text(color="Error", text=text, c_type="text", params=None)
        report_html += "<td class=\"product_table\">" + text + "</td>"
        report_html += "</tr>\n"
    report_html += "</table></p>"

    return {"report_txt": report_txt, "report_html": report_html, "report_dict": product_data}

def get_vulnerability_types_report(combined_cve_data_all, cve_scores, config, source):
    report_txt = ""
    report_html = ""
    criticalities = ["Urgent", "Critical", "High", "Medium", "Low", "All"]
    vulnerability_type_data = dict()
    for cve in combined_cve_data_all:
        vulnerability_type = combined_cve_data_all[cve]['vuln_type']
        value = cve_scores[cve]['components']['Criticality of Vulnerability Type']['value']
        comment = cve_scores[cve]['components']['Criticality of Vulnerability Type']['comment']
        cve_level = cve_scores[cve]['level']
        if not vulnerability_type in vulnerability_type_data:
            vulnerability_type_data[vulnerability_type] = dict()
            vulnerability_type_data[vulnerability_type]['cves'] = dict()
            vulnerability_type_data[vulnerability_type]['value'] = value
            vulnerability_type_data[vulnerability_type]['comment'] = comment
            for crit in criticalities:
                vulnerability_type_data[vulnerability_type]['cves'][crit] = list()
        vulnerability_type_data[vulnerability_type]['cves'][cve_level].append(cve)
        vulnerability_type_data[vulnerability_type]['cves']['All'].append(cve)

    report_html = "<p><table class=\"vulnerability_type_table\">"
    report_html += "<tr class=\"vulnerability_type_table\">"
    report_html += "<th class=\"vulnerability_type_table\">" + "Vulnerability Type" + "</th>"
    report_html += "<th class=\"vulnerability_type_table\">" + "Criticality" + "</th>"
    for criticality in ['Urgent', 'Critical', 'High', 'Medium', 'Low', 'All']:
        text = get_colored_text(color=criticality, text= criticality[0][0], c_type="text", params=None)
        report_html += "<th class=\"vulnerability_type_table\">" + text + "</th>"
    # report_html += "<th class=\"vulnerability_type_table\">" + "Comment" + "</th>"
    report_html += "</tr>\n"
    sorted_product_name_list = get_sorted_product_name_list(vulnerability_type_data)
    for vulnerability_type in sorted_product_name_list:
        report_html += "<tr class=\"vulnerability_type_table\">"
        report_html += "<td class=\"vulnerability_type_table\">" + vulnerability_type + "</td>"
        text = str(vulnerability_type_data[vulnerability_type]['value'])
        if text == "0":
            text = get_colored_text(color="Error", text=text, c_type="text", params=None)
        report_html += "<td class=\"vulnerability_type_table\">" + text + "</td>"
        for criticality in ['Urgent', 'Critical', 'High', 'Medium', 'Low', 'All']:
            text = get_cves_count_value_products_table(criticality, vulnerability_type_data, vulnerability_type)
            report_html += "<td class=\"vulnerability_type_table\">" + text + "</td>"
        text = vulnerability_type_data[vulnerability_type]['comment']
        # if text == "Unknown Vulnerability Type":
        #     text = get_colored_text(color="Error", text=text, c_type="text", params=None)
        # report_html += "<td class=\"vulnerability_type_table\">" + text + "</td>"
        report_html += "</tr>\n"
    report_html += "</table></p>"

    return {"report_txt": report_txt, "report_html": report_html}

def get_comments_report(combined_cve_data, cve_scores, profile_data):
    report_txt = ""
    report_html = ""
    criticalities = ["Urgent", "Critical", "High", "Medium", "Low", "All"]
    vulnerability_comment_data = dict()
    for comment_source in profile_data['comments'].keys():
        if not comment_source in vulnerability_comment_data:
            vulnerability_comment_data[comment_source] = dict()
            vulnerability_comment_data[comment_source]['cves'] = dict()
            for crit in criticalities:
                vulnerability_comment_data[comment_source]['cves'][crit] = list()
        for cve in combined_cve_data:
            cve_level = cve_scores[cve]['level']
            if cve in profile_data['comments'][comment_source]:
                vulnerability_comment_data[comment_source]['cves'][cve_level].append(cve)
                vulnerability_comment_data[comment_source]['cves']["All"].append(cve)

    report_html = "<p><table class=\"vulnerability_type_table\">"
    report_html += "<tr class=\"vulnerability_type_table\">"
    report_html += "<th class=\"vulnerability_type_table\">" + "Source" + "</th>"
    for criticality in ['Urgent', 'Critical', 'High', 'Medium', 'Low', 'All']:
        text = get_colored_text(color=criticality, text= criticality[0][0], c_type="text", params=None)
        report_html += "<th class=\"vulnerability_type_table\">" + text + "</th>"
    report_html += "</tr>\n"
    for comment_source in profile_data['comments'].keys():
        report_html += "<tr class=\"vulnerability_type_table\">"
        report_html += "<td class=\"vulnerability_type_table\">" + comment_source + "</td>"
        for criticality in ['Urgent', 'Critical', 'High', 'Medium', 'Low', 'All']:
            text = get_cves_count_value_comments_table(criticality, vulnerability_comment_data, comment_source)
            report_html += "<td class=\"vulnerability_type_table\">" + text + "</td>"
        report_html += "</tr>\n"

    report_html += "</table></p>"
    return {"report_txt": report_txt, "report_html": report_html}

def get_basic_severity_statistics_report(combined_cve_data_all):
    report_txt = ""
    report_html = ""

    all_vulnerabilities = set()
    for vulnerability in combined_cve_data_all:
        all_vulnerabilities.add(vulnerability)

    critical_vulnerability = set()
    high_vulnerability = set()
    medium_vulnerability = set()
    low_vulnerability = set()

    for vulnerability in combined_cve_data_all:
        cvss_base_score = combined_cve_data_all[vulnerability]['cvss_base_score']
        basic_severity = functions_tools.get_rating_from_cvss_base_score(cvss_base_score)
        if basic_severity == "Critical":
            critical_vulnerability.add(vulnerability)
        elif basic_severity == "High":
            high_vulnerability.add(vulnerability)
        elif basic_severity == "Medium":
            medium_vulnerability.add(vulnerability)
        elif basic_severity == "low":
            low_vulnerability.add(vulnerability)

    report_txt += "All vulnerabilities: " + str(len(all_vulnerabilities)) + "\n"
    report_txt += "Critical: " + str(len(critical_vulnerability)) + "\n"
    report_txt += "High: " + str(len(high_vulnerability)) + "\n"
    report_txt += "Medium: " + str(len(medium_vulnerability)) + "\n"
    report_txt += "Low: " + str(len(low_vulnerability)) + "\n"
    report_html += "<ul>" + "\n"
    report_html += "<li>" + "All vulnerabilities: " + str(len(all_vulnerabilities)) + "</li>" + "\n"
    report_html += "<li>" + "Critical: " + str(len(critical_vulnerability)) + "</li>" + "\n"
    report_html += "<li>" + "High: " + str(len(high_vulnerability)) + "</li>" + "\n"
    report_html += "<li>" + "Medium: " + str(len(medium_vulnerability)) + "</li>" + "\n"
    report_html += "<li>" + "Low: " + str(len(low_vulnerability)) + "</li>" + "\n"
    report_html += "</ul>" + "\n"

    return {"report_txt": report_txt, "report_html": report_html}


def get_comments_for_cves(source, processed_cves):
    report_html = ""
    report_list = list()
    if 'comments' in source:
        comments = source['comments']
        for comment_id in comments:
            if comments[comment_id]:
                for line in comments[comment_id].split("\n"):
                    print_line = False
                    for cve in processed_cves:
                        if cve in line:
                            print_line = True
                    if print_line:
                        for cve in processed_cves:
                            line = re.sub(cve, "<b>" + cve + "</b>", line)
                        report_html += "<p>" + comment_id + ": " + line + "</p>" + "\n"
                        report_list.append({"comment_id":line})

    return {"report_html": report_html, "report_list":report_list}

def get_vulnerability_report_for_report_config(cve_related_data, cve_scores, report_config, profile_data):
    json_data = dict()
    html_content = "<center><img class=\"logo\" src=\"" + report_config['vuln_icons_source'] + "/vulristics.png\"></center>"
    html_content += "<center><img class=\"logo2\" src=\"" + report_config['vuln_icons_source'] + "/lpw_avleonov.png\"></center>"

    combined_cve_data = cve_related_data['combined_cve_data_all']

    if report_config['ignore_comments']:
        profile_data['comments'] = {}

    f = open("reports/template.html", "r")
    template = f.read()
    f.close()

    now = datetime.now()
    html_content += "<p><b>Report Name:</b> " + profile_data['report_name'] + "</br>"
    html_content += "<b>Generated:</b> " + now.strftime("%Y-%m-%d %H:%M:%S") + "</p>"


    report_data = get_basic_severity_statistics_report(combined_cve_data)
    name = "Basic Vulnerability Scores"
    # print("== " + name + " ==")
    basic_score_html_content = "<b>" + name + "</b>" + "\n"
    # print(report_data['report_txt'])
    basic_score_html_content += report_data['report_html']

    report_data = get_vvs_statistics_report(cve_scores)
    name = "Vulristics Vulnerability Scores"
    # print("== " + name + " ==")
    vulristics_score_html_content = "<b>" + name + "</b>" + "\n"
    # print(report_data['report_txt'])
    vulristics_score_html_content += report_data['report_html']

    html_content += "<div class=\"row\"> <div class=\"column\">" + vulristics_score_html_content + "</div>" + \
                    "<div class=\"column\">" +  basic_score_html_content + "</div> </div>"
    # ^^^  - two columns with VVS and CVSS

    # list of all products

    report_data = get_products_report(combined_cve_data, cve_scores, report_config, profile_data)
    json_data['products'] = report_data['report_dict']
    name = "Products"
    # print("== " + name + " ==")
    html_content += "<b>" + name + "</b>" + "\n"
    # print(report_data['report_txt'])
    html_content += report_data['report_html']
    html_content += "</br>"

    report_data = get_vulnerability_types_report(combined_cve_data, cve_scores, report_config, profile_data)
    name = "Vulnerability Types"
    # print("== " + name + " ==")
    html_content += "<b>" + name + "</b>" + "\n"
    # print(report_data['report_txt'])
    html_content += report_data['report_html']
    html_content += "</br>"

    if 'comments' in profile_data:
        report_data = get_comments_report(combined_cve_data, cve_scores, profile_data)
        name = "Comments"
        # print("== " + name + " ==")
        html_content += "<b>" + name + "</b>" + "\n"
        # print(report_data['report_txt'])
        html_content += report_data['report_html']
        html_content += "</br>"

    report_data = get_vulristics_score_report(combined_cve_data, cve_scores, report_config, profile_data)
    json_data['vulnerabilities'] = report_data['report_list']
    name = "Vulnerabilities"
    # print("== " + name + " ==")
    html_content += "<b>" + name + "</b>" + "\n"
    # print(report_data['report_txt'])
    html_content += report_data['report_html']


    current_cve_data = combined_cve_data
    exploited_cves = get_vulns_filtered_by_wild_exploited("Yes", current_cve_data, cve_scores)
    report_data = get_type_based_report(exploited_cves, report_config, profile_data, cve_scores)

    name = "Exploitation in the wild detected"
    # print("== " + name + " (" + str(len(report_data['processed_cves'])) + ") ==")
    html_content += "<h3>" + name + " (" + str(len(report_data['processed_cves'])) + ")</h3>" + "\n"
    # print(report_data['report_txt'])
    html_content += report_data['report_html']
    # html_content += get_comments_for_cves(source, report_data['processed_cves'])["report_html"]
    current_cve_data = get_vulns_filtered_not_in_list(report_data['processed_cves'], current_cve_data)

    exploited_cves = get_vulns_filtered_by_public_exploit_exists("Yes", current_cve_data, cve_scores)
    report_data = get_type_based_report(exploited_cves, report_config, profile_data, cve_scores)
    name = "Public exploit exists, but exploitation in the wild is NOT detected"
    # print("== " + name + " (" + str(len(report_data['processed_cves'])) + ") ==")
    html_content += "<h3>" + name + " (" + str(len(report_data['processed_cves'])) + ")</h3>" + "\n"
    # print(report_data['report_txt'])
    html_content += report_data['report_html']
    # html_content += get_comments_for_cves(source, report_data['processed_cves'])["report_html"]
    current_cve_data = get_vulns_filtered_not_in_list(report_data['processed_cves'], current_cve_data)

    ####### Commented legacy blocks from the reports
    # exploitation_more_likely = get_vulns_filtered_by_exploitation_likeliness("Exploitation More Likely",
    #                                                                          current_cve_data, cve_scores)
    # report_data = get_type_based_repot(exploitation_more_likely, report_config, source)
    # name = "Exploitation more likely"
    # print("== " + name + " (" + str(len(report_data['processed_cves'])) + ") ==")
    # html_content += "<h3>" + name + " (" + str(len(report_data['processed_cves'])) + ")</h3>" + "\n"
    # print(report_data['report_txt'])
    # html_content += report_data['report_html']
    # # html_content += get_comments_for_cves(source, report_data['processed_cves'])["report_html"]
    # current_cve_data = get_vulns_filtered_not_in_list(report_data['processed_cves'], current_cve_data)

    # report_data = get_product_based_repot(current_cve_data, min_cve_number=5, report_config=report_config,
    #                                       source=source, cve_scores)
    # name = "Other Product based "
    # print("== " + name + " (" + str(len(report_data['processed_cves'])) + ") ==")
    # html_content += "<h3>" + name + " (" + str(len(report_data['processed_cves'])) + ")</h3>" + "\n"
    # print(report_data['report_txt'])
    # html_content += report_data['report_html']
    # # html_content += get_comments_for_cves(source, report_data['processed_cves'])["report_html"]
    # current_cve_data = get_vulns_filtered_not_in_list(report_data['processed_cves'], current_cve_data)

    report_data = get_type_based_report(current_cve_data, report_config, profile_data, cve_scores)
    name = "Other Vulnerabilities"
    # print("== " + name + " (" + str(len(report_data['processed_cves'])) + ") ==")
    html_content += "<h3>" + name + " (" + str(len(report_data['processed_cves'])) + ")</h3>" + "\n"
    # print(report_data['report_txt'])
    html_content += report_data['report_html']
    # html_content += get_comments_for_cves(source, report_data['processed_cves'])["report_html"]
    current_cve_data = get_vulns_filtered_not_in_list(report_data['processed_cves'], current_cve_data)

    new_html_full = copy.copy(template)
    html_content = new_html_full.replace("##Content##", html_content)

    return {"html_content": html_content, 'json_data': json_data}

def get_profile(file_path):
    functions_tools.print_debug_message("Reading existing profile " + file_path + "...")
    f = open(file_path, "r")
    profile = json.loads(f.read())
    f.close()
    return profile


def get_cves_to_exclude(profile, source_id):
    cves_to_exclude = set()
    if 'cves_exclude_text' in profile[source_id]:
        cves_exclude_text = profile[source_id]['cves_exclude_text']
        for line in cves_exclude_text.split("\n"):
            if re.findall("^CVE", line.upper()):
                cves_to_exclude.add(line.upper())
            if re.findall("^BDU", line.upper()):
                cves_to_exclude.add(line.upper())
    functions_tools.print_debug_message("Exclude CVEs: " + str(len(cves_to_exclude)))
    return cves_to_exclude


def get_all_cves(profile, source_id, cves_to_exclude):
    cves_text = profile[source_id]['cves_text']
    all_cves = set()
    for line in cves_text.split("\n"):
        if re.findall("^CVE", line.upper()):
            if line.upper() not in cves_to_exclude:
                all_cves.add(line.upper())
        if re.findall("^BDU", line.upper()):
            if line.upper() not in cves_to_exclude:
                all_cves.add(line.upper())
    all_cves = list(all_cves)
    all_cves.sort()
    functions_tools.print_debug_message("All CVEs: " + str(len(all_cves)))
    return all_cves

def get_products(profile, source_id):
    all_prodcts = set()
    if 'products_text' in profile[source_id]:
        products_text = profile[source_id]['products_text']
        for line in products_text.split("\n"):
            all_prodcts.add(line.upper())
        functions_tools.print_debug_message("All products to analyze: " + str(len(all_prodcts)))
    else:
        functions_tools.print_debug_message("No specified products to analyze set in profile, reporting everything")
    return all_prodcts

def print_unclassified_products_templates(cve_scores, cve_related_data):
    unclassified_products = set()
    for cve in cve_scores:
        if cve_scores[cve]['components']['Vulnerable Product is Common']['comment'] == "Unclassified Product":
            unclassified_products.add(cve_related_data['combined_cve_data_all'][cve]['vuln_product'])
    unclassified_products = list(unclassified_products)
    unclassified_products.sort()
    if unclassified_products != list():
        functions_tools.print_debug_message("Add this to data_classification_products.py")
        for product in unclassified_products:
            if "Windows" in product:
                print('''    "''' + product + '''": {
            "prevalence": 0.8,
            "description": "Windows component",
            "additional_detection_strings": []
        },''')
            else:
                print('''    "''' + product + '''": {
            "prevalence": 0,
            "description": "",
            "additional_detection_strings": []
        },''')


def make_html_vulnerability_reports_for_all_report_configs(profile, source_id, cve_related_data, cve_scores,
                                                           result_config):
    functions_tools.print_debug_message("Making vulnerability reports for each reports config...")
    for report_config_name in data_report_configs.patch_tuesday_report_configs:
        functions_tools.print_debug_message("Report config: " + report_config_name)
        report_config = data_report_configs.patch_tuesday_report_configs[report_config_name]
        profile_data = profile[source_id]
        vulnerability_report = get_vulnerability_report_for_report_config(cve_related_data=cve_related_data,
                                                                          cve_scores=cve_scores,
                                                                          report_config=report_config,
                                                                          profile_data=profile_data)

        if 'html' in result_config['result_formats']:
            if not result_config['result_html_path']:
                report_file_path = "reports/" + profile_data['file_name_prefix'] + "_" + report_config[
                    'file_name_suffix'] + ".html"
            else:
                report_file_path = result_config['result_html_path']
            f = open(report_file_path, "w", encoding="utf-8")
            f.write(vulnerability_report['html_content'])
            f.close()
            print("HTML report generated: " + report_file_path)

        if 'json' in result_config['result_formats'] and result_config['result_json_path']:
            json_report_data = {
                "source_id": source_id,
                "data": vulnerability_report['json_data']
            }

            report_file_path = result_config['result_json_path']
            f = open(result_config['result_json_path'], "w")
            f.write(json.dumps(json_report_data, indent=4))
            f.close()

            print("JSON report generated: " + report_file_path)


def get_eanbled_data_sources(profile, source_id):
    all_data_sources = ['ms', 'nvd', 'epss', 'vulners', 'attackerkb', 'bdu', 'custom']
    if 'data_sources' in profile[source_id]:
        enabled_data_sources = profile[source_id]['data_sources']
    else:
        enabled_data_sources = all_data_sources
    return enabled_data_sources


def make_vulnerability_report_for_profile(profile_file_path, source_config, result_config):
    profile = get_profile(profile_file_path)
    source_id = list(profile.keys())[0]
    profile[source_id]['product_data'] = data_classification_products.get_product_data()
    cves_to_exclude = get_cves_to_exclude(profile, source_id)
    all_products_to_analyze = get_products(profile, source_id)

    # making list of CVEs not about products in products_to_analyze to exclude it
    if len(all_products_to_analyze) == 0:
        selected_cves_to_exclude = cves_to_exclude
    else:
        all_cves_tmp= get_all_cves(profile, source_id, cves_to_exclude)
        if source_config['data_sources'] == []:
            enabled_data_sources = get_eanbled_data_sources(profile, source_id) # Get data sources from profile
        else:
            enabled_data_sources = source_config['data_sources'] # Get command line
        print("Enabled data sources: " + str(enabled_data_sources))
        cve_related_data_tmp, cves_to_exclude = functions_combined_vulnerability_data.collect_cve_related_data(
                                                enabled_data_sources, all_cves_tmp, cves_to_exclude,
                                                profile[source_id]['product_data'], source_config)
        selected_cves_to_exclude = cves_to_exclude
        for selected_cve in all_cves_tmp:
            functions_tools.print_debug_message("filtering " + selected_cve + " for one of products_to_analyze")
            b_product_found = False
            for list_type_str in cve_related_data_tmp: 
                functions_tools.print_debug_message("    checking in " + list_type_str)
                if not selected_cve in cve_related_data_tmp[list_type_str]:
                    functions_tools.print_debug_message("      no data for " + selected_cve + " in " + list_type_str)
                    continue
                if not 'vuln_product' in cve_related_data_tmp[list_type_str][selected_cve]:
                    functions_tools.print_debug_message("      no vuln_product for " + selected_cve + " in " + list_type_str)
                    continue
                product_name = (cve_related_data_tmp[list_type_str][selected_cve]['vuln_product']).upper()
                for product_name_from_list in all_products_to_analyze:
                    product_name_from_list = product_name_from_list.upper()
                    if product_name_from_list in product_name:
                        b_product_found = True
                        functions_tools.print_debug_message("                 found")

            if not b_product_found:
                selected_cves_to_exclude.add(selected_cve)
                functions_tools.print_debug_message("- final result: no one of products_to_analyze found")
            else:    
                functions_tools.print_debug_message("- final result: some of products_to_analyze found")

    # collecting data without filtered out CVEs
    all_cves = get_all_cves(profile, source_id, selected_cves_to_exclude)
    if source_config['data_sources'] == []:
        enabled_data_sources = get_eanbled_data_sources(profile, source_id)  # Get data sources from profile
    else:
        enabled_data_sources = source_config['data_sources']  # Get command line
    print("Enabled data sources: " + str(enabled_data_sources))
    cve_related_data, selected_cves_to_exclude = functions_combined_vulnerability_data.collect_cve_related_data(
                                                    enabled_data_sources, all_cves, selected_cves_to_exclude,
                                                    profile[source_id]['product_data'], source_config)
    cve_scores = functions_score.get_cve_scores(all_cves, cve_related_data, profile[source_id])

    print_unclassified_products_templates(cve_scores, cve_related_data)
    make_html_vulnerability_reports_for_all_report_configs(profile, source_id, cve_related_data, cve_scores,
                                                           result_config)

