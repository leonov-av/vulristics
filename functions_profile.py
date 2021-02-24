import json

def save_profile(file_name, report_id, report_name, file_name_prefix, cves_text, comments=[]):
    data = {
        report_id: {
            'report_name': report_name,
            'file_name_prefix': file_name_prefix,
            'cves_text': cves_text,
            'comments': comments
        }
    }

    f = open("data/profiles/" + file_name, "w")
    f.write(json.dumps(data, indent=4))
    f.close()
