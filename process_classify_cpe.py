import urllib.request
import zipfile
import xml.etree.ElementTree as ET
import json

def get_xml_content(zip_path):
    # Open the zip file
    with zipfile.ZipFile(zip_path, "r") as zip_ref:
        # Get the names of all files in the zip
        file_names = zip_ref.namelist()

        # Read the text from the first file in the zip
        with zip_ref.open(file_names[0]) as file:
            xml_content = file.read().decode("utf-8")
    return xml_content


cpe_dict_url = "https://nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.zip"
cpe_dict_zip_path = "data/classification/cpe_dictionary.zip"
# urllib.request.urlretrieve(cpe_dict_url, cpe_dict_zip_path)
# xml_content = get_xml_content(cpe_dict_zip_path)
# root = ET.fromstring(xml_content)

# Debug
tree = ET.parse('data/classification/small.xml')
root = tree.getroot()

cpe_dict = dict()
for root_child in root:
    if root_child.tag == "{http://cpe.mitre.org/dictionary/2.0}cpe-item":
        cpe_id = root_child.attrib['name']
        cpe_dict[cpe_id] = dict()
        for cpe_item_child in root_child:
            if cpe_item_child.tag == "{http://cpe.mitre.org/dictionary/2.0}title":
                cpe_dict[cpe_id]['title'] = cpe_item_child.text
            elif cpe_item_child.tag == "{http://scap.nist.gov/schema/cpe-extension/2.3}cpe23-item":
                cpe_dict[cpe_id]['cpe23-item'] = cpe_item_child.attrib['name']
            else:
                print(cpe_item_child.tag)
print(cpe_dict)