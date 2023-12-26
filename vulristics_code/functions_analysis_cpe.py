import json
import os
import copy

def get_known_short_cpes_dict():
    known_short_cpes = dict()
    if os.path.isfile("data/classification/cpe_dict.json"):
        f = open("data/classification/cpe_dict.json", "r")
        known_short_cpes = json.loads(f.read())
        f.close()
    return known_short_cpes

def get_short_cpe2product_name(product_data):
    short_cpe2product_name = dict()
    for product in product_data:
        if 'short_cpes' in product_data[product]:
            for short_cpe in product_data[product]['short_cpes']:
                short_cpe2product_name[short_cpe] = product
    return short_cpe2product_name

def get_products_by_cpe(short_cpes, short_cpe2product_name, product_data, known_short_cpes_dict, max_full_description):
    products = list()
    short_cpes = list(short_cpes)
    short_cpes.sort(reverse=True)
    for short_cpe in short_cpes:
        # Only analyse for applications
        if short_cpe in short_cpe2product_name:
            product_name = short_cpe2product_name[short_cpe]
            products.append({'product': product_name,
             'source': 'nvd_cve_data_all',
             'detection_type': 'cpe',
             'description': max_full_description,
             'product_data': copy.copy(product_data[product_name])
             })
        elif short_cpe in known_short_cpes_dict:
            product_name = known_short_cpes_dict[short_cpe]['product']
            product_data_value = copy.copy(product_data["DEFAULT_CPE_detected_product"])
            product_data_value['description'] = 'Product detected by ' + str(short_cpe) + ' (exists in CPE dict)'
            products.append({'product': product_name,
             'source': 'nvd_cve_data_all',
             'detection_type': 'cpe',
             'description': max_full_description,
             'product_data': product_data_value
             })
        else:
            product_name = short_cpe.split(":")[2]
            product_data_value = copy.copy(product_data["DEFAULT_CPE_detected_product"])
            product_data_value['description'] = 'Product detected by ' + str(short_cpe) + ' (does NOT exist in CPE dict)'
            products.append({'product': product_name,
             'source': 'nvd_cve_data_all',
             'detection_type': 'cpe',
             'description': max_full_description,
             'product_data': product_data_value
             })
    return products
