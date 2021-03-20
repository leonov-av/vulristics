import json


def save_profile(file_path, report_id, report_name, file_name_prefix, cves_text,
                 data_sources=None, comments=None):
    data = {
        report_id: {
            'report_name': report_name,
            'file_name_prefix': file_name_prefix,
            'cves_text': cves_text,
        }
    }
    if comments:
        data[report_id]['comments'] = comments
    if data_sources:
        data[report_id]['data_sources'] = data_sources
    f = open(file_path, "w")
    f.write(json.dumps(data, indent=4))
    f.close()
