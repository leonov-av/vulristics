import functions_source_ms_cve
import functions_source_analytic_sites
import functions_tools
import functions_profile
import datetime
import re


def get_ms_date(normal_date):
    # "10/13/2020"
    date_time_obj = datetime.datetime.strptime(normal_date, '%Y-%m-%d')
    ms_date = date_time_obj.strftime("%m/%d/%Y")
    return ms_date


def get_second_tuesday(year, long_month_name):
    # Getting second tuesday of a month for MS Patch Tuesday date
    # year = "2020"
    # long_month_name = "October"
    datetime_object = datetime.datetime.strptime(long_month_name, "%B")
    month_number = datetime_object.month
    tuesdays = list()
    for day_number in range(1, 28):
        day_str = str(year) + '-' + str(month_number) + '-' + str(day_number)
        date_time_str = day_str
        date_time_obj = datetime.datetime.strptime(date_time_str, '%Y-%m-%d')
        day_of_the_week = date_time_obj.strftime("%A")
        if day_of_the_week == "Tuesday":
            tuesdays.append(day_str)
    return tuesdays[1]


def get_other_ms_cves(from_date, to_date, patch_tuesdays):
    all_cves = functions_source_ms_cve.get_ms_cves_for_date_range(from_date, to_date)
    print(len(all_cves))
    for patch_tuesday in patch_tuesdays:
        print(patch_tuesday)
        patch_tuesday_date = get_second_tuesday(year=patch_tuesday[0],  long_month_name=patch_tuesday[1])
        patch_tuesday_cves = functions_source_ms_cve.get_ms_cves_for_date_range(patch_tuesday_date, patch_tuesday_date)
        all_cves = all_cves - patch_tuesday_cves
        print(len(all_cves))
    all_cves_txt = re.sub(" ","", "\n".join(all_cves))
    return all_cves_txt


def create_profile(month, year, patch_tuesday_date, file_name):
    # This profile (json file) will describe Microsoft Patch Tuesday reports
    # month = "October"
    # year = "2020"
    # patch_tuesday_date = "10/13/2020"

    functions_tools.print_debug_message("Year: " + year)
    functions_tools.print_debug_message("Month: " + month)
    functions_tools.print_debug_message("Date: " + patch_tuesday_date)
    ms_cves_for_date_range = functions_source_ms_cve.get_ms_cves_for_date_range(patch_tuesday_date,
                                                                                patch_tuesday_date)
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

    queries = [
        "site:https://www.thezdi.com/blog Microsoft Patches for " + month + " " + year
    ]
    zdi_link = functions_source_analytic_sites.get_duckduckgo_search_results_multiple_queries(queries)
    zdi_text = functions_source_analytic_sites.get_zdi_text_from_url(zdi_link['url'])
    functions_tools.print_debug_message("ZDI query: " + query)
    functions_tools.print_debug_message("ZDI url found: " + zdi_link['url'])
    functions_tools.print_debug_message("=== ZDI text ===")
    functions_tools.print_debug_message(zdi_text)
    functions_tools.print_debug_message("=== End of ZDI text ===")

    comments = {
        'qualys': qualys_text,
        'tenable': tenable_text,
        'rapid7': rapid7_text,
        'zdi': zdi_text
    }

    report_id = month + " " + year
    report_name = 'Microsoft Patch Tuesday, ' + month + " " + year
    file_name_prefix = "ms_patch_tuesday_" + month.lower() + year
    cves_text = ms_cves_for_date_range

    data_sources = None # Use all data sources
    functions_profile.save_profile("data/profiles/" + file_name, report_id, report_name, file_name_prefix, cves_text,
                 data_sources, comments)
