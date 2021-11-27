import data_classification_products
import data_classification_vulnerability_types
import copy
import re

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
        match = re.search(r"\b" + re.escape(str(search_string)) + r"\b", value_string)
        if match:
            range = dict()
            range['start']  = match.start() + last_end
            range['end'] = match.end() + last_end
            ranges.append(range)
            value_string = value_string[range['end']:]
            last_end = match.end()
        else:
            continue_processing = False
    return ranges


def get_detected_entities(sentence, detection_entities):
    """
    Make keyword-based detection is sentence based on entities (products, vuln types) from detection_entities
    :param sentence:
    :param detection_entities:
    :return:
    """
    detected_entities = dict()
    for entity in detection_entities:
        detection_strings = set()
        for detection_string in detection_entities[entity]['additional_detection_strings']:
            detection_strings.add(detection_string)
        detection_strings.add(entity)
        detection_strings.add(entity.lower())
        temp_ranges = list()
        for detection_string in detection_strings:
            temp_ranges += get_ranges(sentence, detection_string)
        if temp_ranges != list():
            detected_entities[entity] = copy.copy(temp_ranges)
    return detected_entities


def get_products_from_description(source, description, product_data):
    """
    Get product from the description
    """
    detected_entities = get_detected_entities(description, product_data)
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


def get_vulnerability_type_from_description(source, full_description, vulnerability_data):
    """
    Get vulnerability type from the description
    """
    detected_entities = get_detected_entities(full_description, vulnerability_data)
    results = list()
    for vulnerability_type in detected_entities:
        result = dict()
        result['vuln_type'] = vulnerability_type
        result['source'] = source
        result['description'] = full_description
        result['ranges'] = detected_entities[vulnerability_type]
        result['vuln_type_data'] = vulnerability_data[vulnerability_type]
        results.append(result)
    return results

