import functions_source_ms_cve
import functions_source_analytic_sites
import functions_tools
import json
import datetime

def get_ms_date(normal_date):
    # "10/13/2020"
    date_time_obj = datetime.datetime.strptime(normal_date, '%Y-%m-%d')
    ms_date = date_time_obj.strftime("%m/%d/%Y")
    return (ms_date)

def create_profile(month,year,patch_tuesday_date):
    # This profile (json file) will describe Microsoft Patch Tuesday report
    # month = "October"
    # year = "2020"
    # patch_tuesday_date = "10/13/2020"

    functions_tools.print_debug_message("Year: " + year)
    functions_tools.print_debug_message("Month: " + month)
    ms_patch_tuesday_date = get_ms_date(patch_tuesday_date)  # patch_tuesday_date = "10/13/2020"
    functions_tools.print_debug_message("Date: " + patch_tuesday_date + " (" + ms_patch_tuesday_date + ")")
    ms_cves_for_date_range = functions_source_ms_cve.get_ms_cves_for_date_range(ms_patch_tuesday_date, ms_patch_tuesday_date)
    functions_tools.print_debug_message("MS CVEs found: " + str(len(ms_cves_for_date_range)))
    ms_cves_for_date_range = "\n".join(ms_cves_for_date_range)

    query = month + " " + year + " " + "Patch Tuesday"

    qualys_link = functions_source_analytic_sites.get_qualys_link(query)
    qualys_text = functions_source_analytic_sites.get_qualys_text_from_url(qualys_link['url'])
    functions_tools.print_debug_message("Qualys query: " + query)
    functions_tools.print_debug_message("Qualys url found: " + qualys_link['url'])
    functions_tools.print_debug_message("=== Qualys text ===")
    functions_tools.print_debug_message(qualys_text)
    functions_tools.print_debug_message("=== End of Qualys text ===")

    tenable_link = functions_source_analytic_sites.get_tenable_link(query)
    tenable_text = functions_source_analytic_sites.get_tenable_text_from_url(tenable_link['url'])
    functions_tools.print_debug_message("Tenable query: " + query)
    functions_tools.print_debug_message("Tenable url found: " + tenable_link['url'])
    functions_tools.print_debug_message("=== Tenable text ===")
    functions_tools.print_debug_message(tenable_text)
    functions_tools.print_debug_message("=== End of Tenable text ===")

    rapid7_link = functions_source_analytic_sites.get_rapid7_link(query)
    rapid7_text = functions_source_analytic_sites.get_rapid7_text_from_url(rapid7_link['url'])
    functions_tools.print_debug_message("Rapid7 query: " + query)
    functions_tools.print_debug_message("Rapid7 url found: " + rapid7_link['url'])
    functions_tools.print_debug_message("=== Rapid7 text ===")
    functions_tools.print_debug_message(rapid7_text)
    functions_tools.print_debug_message("=== End of Rapid7 text ===")

    query = "site:https://www.zerodayinitiative.com/blog Microsoft Patches for " + month + " " + year
    zdi_link = functions_source_analytic_sites.get_duckduckgo_search_results(query)
    zdi_text = functions_source_analytic_sites.get_zdi_text_from_url(zdi_link['url'])
    functions_tools.print_debug_message("ZDI query: " + query)
    functions_tools.print_debug_message("ZDI url found: " + zdi_link['url'])
    functions_tools.print_debug_message("=== ZDI text ===")
    functions_tools.print_debug_message(zdi_text)
    functions_tools.print_debug_message("=== End of ZDI text ===")

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

