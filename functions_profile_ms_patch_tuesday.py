import functions_source_ms_cve
import functions_source_analytic_sites
import json

def create_profile(month,year,patch_tuesday_date):
    # month = "October"
    # year = "2020"
    # patch_tuesday_date = "10/13/2020"

    ms_cves_for_date_range = functions_source_ms_cve.get_ms_cves_for_date_range(patch_tuesday_date, patch_tuesday_date)
    ms_cves_for_date_range = "\n".join(ms_cves_for_date_range)

    print("---")

    query = month + " " + year + " " + "Patch Tuesday"

    qualys_link = functions_source_analytic_sites.get_qualys_link(query)
    qualys_text = functions_source_analytic_sites.get_qualys_text_from_url(qualys_link['url'])
    print(qualys_link['url'])
    print(qualys_text)

    print("---")

    tenable_link = functions_source_analytic_sites.get_tenable_link(query)
    tenable_text = functions_source_analytic_sites.get_tenable_text_from_url(tenable_link['url'])
    print(tenable_link['url'])
    print(tenable_text)

    print("---")

    rapid7_link = functions_source_analytic_sites.get_rapid7_link(query)
    rapid7_text = functions_source_analytic_sites.get_rapid7_text_from_url(rapid7_link['url'])
    print(rapid7_link['url'])
    print(rapid7_text)

    print("---")

    query = "site:https://www.zerodayinitiative.com/blog Microsoft Patches for " + month + " " + year
    zdi_link = functions_source_analytic_sites.get_duckduckgo_search_results(query)
    zdi_text = functions_source_analytic_sites.get_zdi_text_from_url(zdi_link['url'])
    print(zdi_link['url'])
    print(zdi_text)


    data = {
        month + " " + year: {
            'report_name': 'Microsoft Patch Tuesday, ' + month + " " + year,
            'file_name_prefix': month.lower() + year,
            'cves_text': ms_cves_for_date_range,
            'comments': {
                'qualys': qualys_text,
                'tenable': tenable_text,
                'rapid7': rapid7_text,
                'zdi': zdi_text
            }
        }
    }

    f = open("data/profile_ms_patch_tuesday/" + month.lower() + year + ".json", "w")
    f.write(json.dumps(data,indent=4))
    f.close()

