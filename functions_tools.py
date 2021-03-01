def get_sorted_list_from_weighted_dict(dictionary):
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
    if int(cvss_base_score) > 0 and int(cvss_base_score) < 4:
        cvss_rating = "Low"
    elif int(cvss_base_score) >= 4 and int(cvss_base_score) < 7:
        cvss_rating = "Medium"
    elif int(cvss_base_score) >= 7 and int(cvss_base_score) < 9:
        cvss_rating = "High"
    elif int(cvss_base_score) >= 9:
        cvss_rating = "Critical"
    return cvss_rating


def print_debug_message(message):
    print(message)