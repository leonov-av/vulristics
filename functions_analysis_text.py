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

def analyse_sentence(sentence):
    """
    Get product and vulnerability_type from the sentence
    :param sentence:
    :return:
    """
    detected_products = get_detected_entities(sentence, data_classification_products.product_data)
    max_priority = 0
    detected_product_name = ""
    for product in detected_products:
        if data_classification_products.product_data[product]['priority'] > max_priority:
            max_priority = data_classification_products.product_data[product]['priority']
            detected_product_name = product

    detected_vulnerability_types = get_detected_entities(sentence,
                                                data_classification_vulnerability_types.vulnerability_type_data)
    max_criticality = 0
    detected_vulnerability_type = ""
    for vulnerability_type in detected_vulnerability_types:
        if data_classification_vulnerability_types.vulnerability_type_data[vulnerability_type]['criticality'] > max_criticality:
            max_criticality = data_classification_vulnerability_types.vulnerability_type_data[vulnerability_type]['criticality']
            detected_vulnerability_type = vulnerability_type
    return {
                "detected_product_name": detected_product_name,
                "detected_products": detected_products,
                "detected_vulnerability_type":detected_vulnerability_type,
                "detected_vulnerability_types":detected_vulnerability_types
            }

def old_get_html(block):
    print_block = re.sub("\[sentence_delim\]","",block['processed_block'])
    print_block = re.sub("\[newline\]", "", print_block)
    for tag in block['tags']:
        print_block = re.sub('\[' + tag['text'] + '\|' + tag['param_name'] + '=\'' + tag['param_value'] +
                             '\'\]','<span class="' + tag['param_name'] + '">' + tag['text'] + '</span>',print_block)
    return(print_block)