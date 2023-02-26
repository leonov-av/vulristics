import requests
import credentials
import zipfile
import data_classification_vulnerability_types
import data_classification_products
import re
import json

def update_product_data(products):
    f = open("data/classification/products.json","w")
    f.write(json.dumps(products, indent=4))
    f.close()


# Download MS CVEs from Vulners
def download_ms_cves():
    name = "mscve"
    api_key = credentials.vulners_key
    response = requests.get('https://vulners.com/api/v3/archive/collection/?type=' + name + '&apiKey=' + api_key)
    with open('data/classification/' + name + '.zip', 'wb') as f:
        f.write(response.content)
        f.close()


def get_ms_cves():
    name = "mscve"
    archive = zipfile.ZipFile('data/classification/' + name + ".zip")
    archived_file = archive.open(archive.namelist()[0])
    archive_content = json.loads(archived_file.read())
    archived_file.close()
    return archive_content


def get_ms_software_names_candidates():
    all_titles = list()
    for object in get_ms_cves():
        all_titles.append(object['_source']['title'])

    vuln_types = set()
    for title in data_classification_vulnerability_types.vulnerability_type_data:
        vuln_types.add(title)
    for title in data_classification_vulnerability_types.vulnerability_type_detection_patterns:
        title = re.sub(" Vulnerability$", "", title)
        vuln_types.add(title)

    software_names = set()
    for title in all_titles:
        title = re.sub(" ", " ", title)
        if re.findall(" Vulnerability$",title):
            title = re.sub(" Vulnerability$", "", title)
            matched = False
            for vuln_type in vuln_types:
                if re.findall(" " + vuln_type + "$", title):
                    software_name = re.sub(" " + vuln_type + "$", "", title)
                    if not software_name in ["GitHub: CVE-2022-41953 Git GUI Clone"]:
                        software_names.add(software_name)
                        matched = True
            # if not matched:
            #     print(title)
            #     print(vuln_types)
    return software_names


def update_products_file_from_vulners_ms_cves():
    download_ms_cves()

    # Adding new product_objects
    product_objects = data_classification_products.get_product_data()
    all_additional_detection_strings = set()
    all_software_names = set()
    for object_software_name in product_objects:
        all_software_names.add(object_software_name)
        if product_objects[object_software_name]['additional_detection_strings'] != "":
            for additional_detection_string in product_objects[object_software_name]['additional_detection_strings']:
                all_additional_detection_strings.add(additional_detection_string)

    ms_software_names_candidates = get_ms_software_names_candidates()
    for ms_software_names_candidate in ms_software_names_candidates:
        if not ms_software_names_candidate in all_software_names and \
                not ms_software_names_candidate in all_additional_detection_strings:
            if "Windows" in ms_software_names_candidate:
                product_objects[ms_software_names_candidate] = {
                    "prevalence": 0.8,
                    "description": "Windows component",
                    "additional_detection_strings": []
                }
            else:
                product_objects[ms_software_names_candidate] = {
                    "prevalence": 0.5,
                    "description": "",
                    "additional_detection_strings": []
                }

    # Adding vendor "Microsoft"
    for ms_software_names_candidate in ms_software_names_candidates:
        if ms_software_names_candidate in product_objects:
            product_objects[ms_software_names_candidate]['vendor'] = "Microsoft"

    # Adding vendor "Windows component" in description if not set
    for ms_software_names_candidate in ms_software_names_candidates:
        if ms_software_names_candidate in product_objects:
            if "Windows" in ms_software_names_candidate and  \
                    product_objects[ms_software_names_candidate]['description'] == "":
                product_objects[ms_software_names_candidate]['description'] = "Windows component"

    update_product_data(product_objects)


update_products_file_from_vulners_ms_cves()