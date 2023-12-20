import urllib.request
import zipfile
import xml.etree.ElementTree as ET
import json
import html
from urllib.parse import unquote

head = '''<?xml version='1.0' encoding='UTF-8'?>
<cpe-list xmlns:config="http://scap.nist.gov/schema/configuration/0.1" xmlns="http://cpe.mitre.org/dictionary/2.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:scap-core="http://scap.nist.gov/schema/scap-core/0.3" xmlns:cpe-23="http://scap.nist.gov/schema/cpe-extension/2.3" xmlns:ns6="http://scap.nist.gov/schema/scap-core/0.1" xmlns:meta="http://scap.nist.gov/schema/cpe-dictionary-metadata/0.2" xsi:schemaLocation="http://scap.nist.gov/schema/cpe-extension/2.3 https://scap.nist.gov/schema/cpe/2.3/cpe-dictionary-extension_2.3.xsd http://cpe.mitre.org/dictionary/2.0 https://scap.nist.gov/schema/cpe/2.3/cpe-dictionary_2.3.xsd http://scap.nist.gov/schema/cpe-dictionary-metadata/0.2 https://scap.nist.gov/schema/cpe/2.1/cpe-dictionary-metadata_0.2.xsd http://scap.nist.gov/schema/scap-core/0.3 https://scap.nist.gov/schema/nvd/scap-core_0.3.xsd http://scap.nist.gov/schema/configuration/0.1 https://scap.nist.gov/schema/nvd/configuration_0.1.xsd http://scap.nist.gov/schema/scap-core/0.1 https://scap.nist.gov/schema/nvd/scap-core_0.1.xsd">
'''
tail = "</cpe-list>"

def update_cpe_dict(cpe_item, cpe_dict):
    string = head + cpe_item + tail
    root = ET.fromstring(string)
    for root_child in root:
        if root_child.tag == "{http://cpe.mitre.org/dictionary/2.0}cpe-item":
            cpe_id = root_child.attrib['name']
            type = cpe_id.split(":")[1]
            vendor_low = unquote(cpe_id.split(":")[2])
            product_low = unquote(cpe_id.split(":")[3])

            # print(vendor_low)
            # print(product_low)

            if type == "/a":
                type = "application"
            elif type == "/o":
                type = "operation system"
            elif type == "/h":
                type = "hardware"

            cpe_id_short = (cpe_id.split(":")[1].replace("/","") + ":" +  cpe_id.split(":")[2] +
                            ":" + cpe_id.split(":")[3])

            cpe_dict[cpe_id_short] = dict()
            cpe_dict[cpe_id_short]['type'] = type
            cpe_dict[cpe_id_short]['references'] = list()
            for cpe_item_child in root_child:
                if cpe_item_child.tag == "{http://cpe.mitre.org/dictionary/2.0}title":
                    cpe_dict[cpe_id_short]['title'] = cpe_item_child.text

                    vendor_right_case = vendor_low
                    product_right_case = product_low
                    title_temp_string = cpe_dict[cpe_id_short]['title'].replace(" ","_").lower()
                    vendor_start = title_temp_string.find(vendor_low)
                    if vendor_start != -1:
                        vendor_right_case = cpe_dict[cpe_id_short]['title'][vendor_start:vendor_start + len(vendor_low)]
                        product_start = title_temp_string.find(product_low, vendor_start + len(vendor_low))
                        if product_start != -1:
                            product_right_case = cpe_dict[cpe_id_short]['title'][product_start:product_start +
                                                                                               len(product_low)]

                    cpe_dict[cpe_id_short]['vendor'] = vendor_right_case
                    cpe_dict[cpe_id_short]['product'] = product_right_case

                elif cpe_item_child.tag == "{http://scap.nist.gov/schema/cpe-extension/2.3}cpe23-item":
                    cpe_dict[cpe_id_short]['cpe23_short'] = (cpe_item_child.attrib['name'].split(":")[0] + ":" +
                                                             cpe_item_child.attrib['name'].split(":")[1] + ":" +
                                                             cpe_item_child.attrib['name'].split(":")[2] + ":" +
                                                             cpe_item_child.attrib['name'].split(":")[3] + ":" +
                                                             cpe_item_child.attrib['name'].split(":")[4])

                elif cpe_item_child.tag == "{http://cpe.mitre.org/dictionary/2.0}references":
                    for reference_item in cpe_item_child:
                        cpe_dict[cpe_id_short]['references'].append({
                            reference_item.text: reference_item.attrib['href']
                        })
                else:
                    print(cpe_item_child.tag)
    return cpe_dict


def update_cpe_dict_json_file(cpe_dict_json_path):
    cpe_dict_url = "https://nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.zip"
    cpe_dir = "data/classification/"
    cpe_file_path = "data/classification/official-cpe-dictionary_v2.3.xml"
    cpe_dict_zip_path = "data/classification/cpe_dictionary.zip"

    urllib.request.urlretrieve(cpe_dict_url, cpe_dict_zip_path)
    with zipfile.ZipFile(cpe_dict_zip_path, 'r') as zip_ref:
        zip_ref.extractall(cpe_dir)

    cpe_file = open(cpe_file_path, 'r')
    cpe_file_lines = cpe_file.readlines()

    cpe_item = ""
    cpe_dict = dict()
    for cpe_file_line in cpe_file_lines:
        if "<cpe-item " in cpe_file_line:
            cpe_item = cpe_file_line
        elif "</cpe-item>" in cpe_file_line:
            cpe_item += cpe_file_line
            update_cpe_dict(cpe_item, cpe_dict)
        else:
            cpe_item += cpe_file_line

    f = open(cpe_dict_json_path, "w")
    f.write(json.dumps(cpe_dict, indent=4))
    f.close()

cpe_dict_json_path = "data/classification/cpe_dict.json"

update_cpe_dict_json_file(cpe_dict_json_path)


# f = open(cpe_dict_json_path, "r")
# cpe_dict = json.loads(f.read())
# f.close()
#
# print(len(cpe_dict))
#
# vendors = set()
# for cpe_id in cpe_dict:
#     vendors.add(cpe_dict[cpe_id]['vendor'])
#
# print(len(vendors))
#
# f = open("data/classification/products.json", "r")
# vulristics_products = json.loads(f.read())
# f.close()
#
# print(len(vulristics_products))



