import urllib.request
import zipfile
import xml.etree.ElementTree as ET
import json

def xml_to_dict(xml_string):
    root = ET.fromstring(xml_string)
    json_data = {}
    json_data[root.tag] = parse_element(root)
    return json_data

def parse_element(element):
    if len(element) == 0:
        return element.text
    else:
        data = {}
        for child in element:
            child_data = parse_element(child)
            if child.tag in data:
                if type(data[child.tag]) is list:
                    data[child.tag].append(child_data)
                else:
                    data[child.tag] = [data[child.tag], child_data]
            else:
                data[child.tag] = child_data
        return data

# URL of the zip file
url = "https://nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.zip"

# Download the zip file
urllib.request.urlretrieve(url, "data/classification/cpe_dictionary.zip")

# Open the zip file
with zipfile.ZipFile("data/classification/cpe_dictionary.zip", "r") as zip_ref:
    # Get the names of all files in the zip
    file_names = zip_ref.namelist()

    # Read the text from the first file in the zip
    with zip_ref.open(file_names[0]) as file:
        xml_content = file.read().decode("utf-8")

dict_data = xml_to_dict(xml_content)
print(dict_data['{http://cpe.mitre.org/dictionary/2.0}cpe-list']['{http://cpe.mitre.org/dictionary/2.0}cpe-item'])