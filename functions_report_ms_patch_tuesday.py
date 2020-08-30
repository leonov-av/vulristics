import re

import data_vulnerability_classification


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


def make_pt_report(ms_cve_data, report_config, source):
    if report_config['ignore_comments']:
        source['comments'] = {}

    f = open("report/template.html", "r")
    template = f.read()
    f.close()
    html_content = "<h1>" + source['report_name'] + "</h1>"

    report_data = get_statics_report(ms_cve_data)
    name = "Statistics"
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

    exploitation_more_likely = get_vulns_filtered_by_exploitation_likeliness("Exploitation More Likely",
                                                                             current_cve_data)
    report_data = get_type_based_repot(exploitation_more_likely, report_config, source)
    name = "Exploitation more likely"
    print("== " + name + " (" + str(len(report_data['processed_cves'])) + ") ==")
    html_content += "<h3>" + name + " (" + str(len(report_data['processed_cves'])) + ")</h3>" + "\n"
    print(report_data['report_txt'])
    html_content += report_data['report_html']
    # html_content += get_comments_for_cves(source, report_data['processed_cves'])["report_html"]
    current_cve_data = get_vulns_filtered_not_in_list(report_data['processed_cves'], current_cve_data)

    report_data = get_product_based_repot(current_cve_data, min_cve_number=5, report_config=report_config,
                                          source=source)
    name = "Other Product based"
    print("== " + name + " (" + str(len(report_data['processed_cves'])) + ") ==")
    html_content += "<h3>" + name + " (" + str(len(report_data['processed_cves'])) + ")</h3>" + "\n"
    print(report_data['report_txt'])
    html_content += report_data['report_html']
    # html_content += get_comments_for_cves(source, report_data['processed_cves'])["report_html"]
    current_cve_data = get_vulns_filtered_not_in_list(report_data['processed_cves'], current_cve_data)

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
