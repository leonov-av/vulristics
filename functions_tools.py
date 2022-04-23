import requests
import credentials


def get_sorted_list_from_weighted_dict(dictionary, combined_cve_data_all=None):
    weight_to_item = dict()
    all_weights = set()
    for item in dictionary:
        all_weights.add(dictionary[item])
        if not dictionary[item] in weight_to_item:
            weight_to_item[dictionary[item]] = list()
        weight_to_item[dictionary[item]].append(item)
    all_weights = list(all_weights)
    all_weights.sort(reverse=True)
    results = list()
    for weight in all_weights:
        if combined_cve_data_all: # Vulnerability sorting
            items = weight_to_item[weight]
            new_id_to_item = dict()
            for item in items:
                new_id_to_item[combined_cve_data_all[item]['vuln_type'] + " - " +
                      combined_cve_data_all[item]['vuln_product'] + " - " + item] = item
            new_ids = list(new_id_to_item.keys())
            new_ids.sort()
            for new_id in new_ids:
                results.append(new_id_to_item[new_id])
        else:
            items = weight_to_item[weight]
            items.sort()
            for item in items:
                results.append(item)
    return (results)


def get_rating_from_cvss_base_score(cvss_base_score):
    # Rating CVSS Score
    # Low 0.1 - 3.9
    # Medium 4.0 - 6.9
    # High 7.0 - 8.9
    # Critical 9.0 - 10.0
    cvss_rating = "N/A"
    if cvss_base_score == "Unknown CVSS Base Score":
        cvss_base_score = 0
    if float(cvss_base_score) > 0 and float(cvss_base_score) < 4:
        cvss_rating = "Low"
    elif float(cvss_base_score) >= 4 and float(cvss_base_score) < 7:
        cvss_rating = "Medium"
    elif float(cvss_base_score) >= 7 and float(cvss_base_score) < 9:
        cvss_rating = "High"
    elif float(cvss_base_score) >= 9:
        cvss_rating = "Critical"
    return cvss_rating


def print_debug_message(message):
    print(message)


def make_request(type, url, headers):
    response = None
    if type == "get":
        if credentials.proxies == {}:
            response = requests.get(url, headers=headers)
        else:
            response = requests.get(url, headers=headers, proxies=credentials.proxies)
    return response
