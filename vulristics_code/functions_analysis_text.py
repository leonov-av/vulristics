import copy
import re

def get_alternative_name2product_name(product_data):
    alternative_name2product_name = dict()
    for product in product_data:
        if 'alternative_names' in product_data[product]:
            for alternative_name in product_data[product]['alternative_names']:
                alternative_name2product_name[alternative_name] = product
    return alternative_name2product_name

def get_ranges(value_string, search_string):
    """
    Search for search_string in value_string and return the ranges for matches
    :param value_string:
    :param search_string:
    :return:
    """
    continue_processing = True
    last_end = 0
    ranges = list()
    while continue_processing:
        # print("search_string: " + search_string)
        match = re.search(r"\b" + re.escape(str(search_string)) + r"\b", value_string)
        match2 = re.search(re.escape(str(search_string)), value_string)
        if match:
            range = dict()
            range['start']  = match.start() + last_end
            range['end'] = match.end() + last_end
            ranges.append(range)
            value_string = value_string[range['end']:]
            last_end = match.end()
        elif match2:
            range = dict()
            range['start']  = match2.start() + last_end
            range['end'] = match2.end() + last_end
            ranges.append(range)
            value_string = value_string[range['end']:]
            last_end = match2.end()
        else:
            continue_processing = False
    return ranges

# ranges = get_ranges(value_string=".NET Framework Denial of Service Vulnerability", search_string=".NET Framework")
# print(ranges)


def get_detected_products(description, product_detection_string2product_name):
    """
    Keyword-based detection of product name
    :param description:
    :param product_detection_string2product_name:
    :return:
    """
    detected_products = dict()
    for detection_string in product_detection_string2product_name:
        if detection_string in description:
            product_name = product_detection_string2product_name[detection_string]
            detected_products[product_name] = get_ranges(description, detection_string)
    return detected_products


def get_detected_vuln_types(full_description, vulnerability_type_data):
    """
    Keyword-based detection of vulnerability type
    :param full_description:
    :param vulnerability_type_data:
    :return:
    """
    detected_entities = dict()
    for entity in vulnerability_type_data:
        detection_strings = set()
        for detection_string in vulnerability_type_data[entity]['additional_detection_strings']:
            detection_strings.add(detection_string)
        detection_strings.add(entity)
        detection_strings.add(entity.lower())
        temp_ranges = list()
        for detection_string in detection_strings:
            temp_ranges += get_ranges(full_description, detection_string)
        if temp_ranges != list():
            detected_entities[entity] = copy.copy(temp_ranges)

    return detected_entities


def get_products_from_description(source, description, product_data,
                                  product_detection_string2product_name):
    """
    Get product from the description
    """
    detected_entities = get_detected_products(description, product_detection_string2product_name)
    results = list()
    for product_name in detected_entities:
        result = dict()
        result['product'] = product_name
        result['source'] = source
        result['description'] = description
        result['ranges'] = detected_entities[product_name]
        if 'detection_priority' not in product_data[product_name]:
            product_data[product_name]['detection_priority'] = 0
        result['product_data'] = product_data[product_name]
        results.append(result)
    return results


def get_vulnerability_type_from_description(source, full_description, vulnerability_type_data):
    """
    Get vulnerability type from the description
    """
    detected_entities = get_detected_vuln_types(full_description, vulnerability_type_data)
    results = list()
    for vulnerability_type in detected_entities:
        result = dict()
        result['vuln_type'] = vulnerability_type
        result['source'] = source
        result['description'] = full_description
        result['ranges'] = detected_entities[vulnerability_type]
        result['vuln_type_data'] = vulnerability_type_data[vulnerability_type]
        results.append(result)
    return results

def get_description_type(full_description):
    """
    Getting description type for potential optimisation
    :param full_description:
    :return:
    """
    description_type = "general"
    if re.findall(" Vulnerability$", full_description):
        description_type = "ms_generated"
    return(description_type)

def get_product_name_structure_ms_generated(product_name, source, full_description, product_data,
                                            alternative_name2product_name,
                                            product_detection_string2product_name):
    product_result = dict()
    product_result['ranges'] = get_ranges(full_description, product_name)

    if product_name in product_detection_string2product_name:
        product_name = product_detection_string2product_name[product_name] # Changing product name to
                                                                           # product name from file
        product_result['product_data'] = product_data[product_name]
    else:
        if "Windows" in product_name:
            product_result['product_data'] = product_data['DEFAULT_Microsoft_Windows_Component']
        else:
            product_result['product_data'] = product_data['DEFAULT_Microsoft_Product']
    if 'detection_priority' not in product_result['product_data']:
        product_result['product_data']['detection_priority'] = 0

    if product_name in alternative_name2product_name:
        product_name = alternative_name2product_name[product_name]

    product_result['detection_type'] = "heuristics_ms"
    product_result['product'] = product_name
    product_result['source'] = source
    product_result['description'] = full_description
    return product_result

def get_vulnerability_type_structure_ms_generated(vulnerability_type, source, full_description, vulnerability_type_data):
    vulnerability_type_result = dict()
    vulnerability_type_result['vuln_type'] = vulnerability_type
    vulnerability_type_result['source'] = source
    vulnerability_type_result['description'] = full_description
    vulnerability_type_result['ranges'] = get_ranges(full_description, vulnerability_type)
    vulnerability_type_result['detection_type'] = "heuristics_ms"
    vulnerability_type_result['vuln_type_data'] = vulnerability_type_data[vulnerability_type]
    return vulnerability_type_result

def get_vulnerability_type_and_product_from_description_ms_generated(source, full_description,
                                                                    product_data,
                                                                    alternative_name2product_name,
                                                                    product_detection_string2product_name,
                                                                    vulnerability_type_data):
    vulnerability_type = ""
    product_name = ""
    results = dict()

    for vuln_type in vulnerability_type_data:
        if vuln_type + " Vulnerability" in full_description:
            vulnerability_type = vuln_type
            product_name = re.sub(" " + vuln_type + " Vulnerability$", "", full_description)

    if vulnerability_type != "" and product_name != "":
        results['detected_products'] = list()
        results['detected_products'].append(get_product_name_structure_ms_generated(product_name, source,
                                                                                full_description,
                                                                                product_data,
                                                                                alternative_name2product_name,
                                                                                product_detection_string2product_name))

        results['detected_vuln_types'] = list()
        results['detected_vuln_types'].append(get_vulnerability_type_structure_ms_generated(vulnerability_type, source,
                                                                                full_description,
                                                                                vulnerability_type_data))

    return results
