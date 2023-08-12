import json


def save_profile(profile_file_path, report_id, report_name, file_name_prefix, cve_list_text,
                 products_text=None, data_sources=None, comments=None):
    data = {
        report_id: {
            'report_name': report_name,
            'file_name_prefix': file_name_prefix,
            'cves_text': cve_list_text,
        }
    }
    if comments:
        data[report_id]['comments'] = comments
    if data_sources:
        data[report_id]['data_sources'] = data_sources
    if products_text:
        data[report_id]['products_text'] = products_text
    f = open(profile_file_path, "w")
    f.write(json.dumps(data, indent=4))
    f.close()
