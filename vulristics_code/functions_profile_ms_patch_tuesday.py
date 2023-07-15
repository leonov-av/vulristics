from vulristics_code import functions_source_analytic_sites, functions_source_ms_cve, functions_tools, functions_profile
import datetime
import time
import re


def get_ms_date(normal_date):
    # "10/13/2020"
    date_time_obj = datetime.datetime.strptime(normal_date, '%Y-%m-%d')
    ms_date = date_time_obj.strftime("%m/%d/%Y")
    return ms_date


def get_patch_tuesday_date_by_year_and_month(year, long_month_name):
    # Getting second tuesday of a month for MS Patch Tuesday date
    # year = "2020"
    # long_month_name = "October"
    datetime_object = datetime.datetime.strptime(long_month_name, "%B")
    month_number = datetime_object.month
    tuesdays = list()
    for day_number in range(1, 28):
        if month_number < 10:
            month_number_str = "0" + str(month_number)
        else:
            month_number_str = str(month_number)
        if day_number < 10:
            day_number_str = "0" + str(day_number)
        else:
            day_number_str = str(day_number)
        day_str = str(year) + '-' + month_number_str + '-' + day_number_str
        date_time_str = day_str
        date_time_obj = datetime.datetime.strptime(date_time_str, '%Y-%m-%d')
        day_of_the_week = date_time_obj.strftime("%A")
        if day_of_the_week == "Tuesday":
            tuesdays.append(day_str)
    patch_tuesday = tuesdays[1]
    return patch_tuesday


def get_patch_tuesday_related_dates(year, long_month_name):
    patch_tuesday = get_patch_tuesday_date_by_year_and_month(year, long_month_name)
    patch_tuesday_ts = int(time.mktime(datetime.datetime.strptime(patch_tuesday, "%Y-%m-%d").timetuple()))
    patch_tuesday_ext_last_date = datetime.datetime.fromtimestamp(patch_tuesday_ts - 24*60*60).strftime('%Y-%m-%d')
    patch_tuesday_ext_first_date_year = datetime.datetime.fromtimestamp(patch_tuesday_ts - 30*24*60*60).strftime('%Y')
    patch_tuesday_ext_first_date_month = datetime.datetime.fromtimestamp(patch_tuesday_ts - 30*24*60*60).strftime('%B')
    previous_patch_tuesday = get_patch_tuesday_date_by_year_and_month(patch_tuesday_ext_first_date_year,
                                                                      patch_tuesday_ext_first_date_month)
    previous_patch_tuesday_ts = int(time.mktime(datetime.datetime.strptime(previous_patch_tuesday,
                                                                           "%Y-%m-%d").timetuple()))
    patch_tuesday_ext_first_date = datetime.datetime.fromtimestamp(previous_patch_tuesday_ts +
                                                                   24*60*60).strftime('%Y-%m-%d')
    return {
                "patch_tuesday": patch_tuesday,
                "patch_tuesday_ext_first_date": patch_tuesday_ext_first_date,
                "patch_tuesday_ext_last_date": patch_tuesday_ext_last_date,
                "previous_patch_tuesday": previous_patch_tuesday
           }


def get_other_ms_cves(from_date, to_date, patch_tuesdays):
    all_cves, all_other_vulns = functions_source_ms_cve.get_ms_vulns_for_date_range(from_date, to_date)

    for patch_tuesday in patch_tuesdays:
        print(patch_tuesday)
        pt_related_dates = get_patch_tuesday_related_dates(year=patch_tuesday[0],
                                                           long_month_name=patch_tuesday[1])
        patch_tuesday_date = pt_related_dates["patch_tuesday"]
        patch_tuesday_cves, patch_tuesday_other_vulns = functions_source_ms_cve.get_ms_vulns_for_date_range(patch_tuesday_date, patch_tuesday_date)
        all_cves = all_cves - patch_tuesday_cves
        print(len(all_cves))
    all_cves_txt = re.sub(" ", "", "\n".join(all_cves))
    return all_cves_txt



def create_profile(pt_type, month, year, pt_related_dates, comments_links, file_name):
    # This profile (json file) will describe Microsoft Patch Tuesday reports
    # month = "October"
    # year = "2020"
    # pt_related_dates = {'patch_tuesday': '2022-02-08', 'patch_tuesday_ext_first_date': '2022-01-12',
    #   'patch_tuesday_ext_last_date': '2022-02-07', 'previous_patch_tuesday': '2022-01-11'}
    comments = dict()

    functions_tools.print_debug_message("MS PT Year: " + year)
    functions_tools.print_debug_message("MS PT Month: " + month)
    functions_tools.print_debug_message("MS PT Date: " + pt_related_dates['patch_tuesday'])
    ms_cves, ms_other_vulns = functions_source_ms_cve.get_ms_vulns_for_date_range(pt_related_dates['patch_tuesday'],
                                                                  pt_related_dates['patch_tuesday'])
    functions_tools.print_debug_message("MS PT CVEs found: " + str(len(ms_cves)))
    if ms_other_vulns != set():
        print("MS PT OTHER VULNS found: " + str(len(ms_other_vulns)))
        print(ms_other_vulns)

    ext_ms_cves = set()
    if pt_type == "Extended":
        functions_tools.print_debug_message("Ext MS PT Date from: " + pt_related_dates['patch_tuesday_ext_first_date'])
        functions_tools.print_debug_message("Ext MS PT Date to: " + pt_related_dates['patch_tuesday_ext_last_date'])

        ext_ms_cves, ext_ms_other_vulns = functions_source_ms_cve.get_ms_vulns_for_date_range(
                                                                        pt_related_dates['patch_tuesday_ext_first_date'],
                                                                        pt_related_dates['patch_tuesday_ext_last_date']
                                                                    )
        functions_tools.print_debug_message("Ext MS PT CVEs found: " + str(len(ext_ms_cves)))
        if ext_ms_other_vulns != set():
            print("Ext MS PT OTHER VULNS found: " + str(len(ms_other_vulns)))
            print(ms_other_vulns)

        ext_ms_comments = list()
        for cve in ext_ms_cves:
            ext_ms_comments.append(cve + " was published before "  + month + " " + str(year) + " Patch Tuesday from " + \
                                   pt_related_dates['patch_tuesday_ext_first_date'] + " to " + \
                                   pt_related_dates['patch_tuesday_ext_last_date'])

        comments["MS PT Extended"] = "\n".join(ext_ms_comments)

    all_ms_cves = ms_cves.union(ext_ms_cves)
    functions_tools.print_debug_message("ALL MS PT CVEs: " + str(len(all_ms_cves)))

    ms_cves = "\n".join(all_ms_cves)

    query = month + " " + year + " " + "Patch Tuesday"

    if "Qualys" in comments_links:
        qualys_link = comments_links["Qualys"]
    else:
        qualys_link = functions_source_analytic_sites.get_qualys_link(query)
    if qualys_link:
        qualys_text = functions_source_analytic_sites.get_qualys_text_from_url(qualys_link['url'])
        qualys_text = functions_source_analytic_sites.process_qualys_text(qualys_text)
        functions_tools.print_debug_message("Qualys query: " + query)
        functions_tools.print_debug_message("Qualys url found: " + qualys_link['url'])
        functions_tools.print_debug_message("=== Qualys text ===")
        functions_tools.print_debug_message(qualys_text)
        functions_tools.print_debug_message("=== End of Qualys text ===")
        comments['qualys'] = qualys_text

    if "Tenable" in comments_links:
        tenable_link = comments_links["Tenable"]
    else:
        tenable_link = functions_source_analytic_sites.get_tenable_link(query)
    if tenable_link:
        tenable_text = functions_source_analytic_sites.get_tenable_text_from_url(tenable_link['url'])
        functions_tools.print_debug_message("Tenable query: " + query)
        functions_tools.print_debug_message("Tenable url found: " + tenable_link['url'])
        functions_tools.print_debug_message("=== Tenable text ===")
        functions_tools.print_debug_message(tenable_text)
        functions_tools.print_debug_message("=== End of Tenable text ===")
        comments['tenable'] = tenable_text

    if "Rapid7" in comments_links:
        rapid7_link = comments_links["Rapid7"]
    else:
        rapid7_link = functions_source_analytic_sites.get_rapid7_link(query)
    if rapid7_link:
        rapid7_text = functions_source_analytic_sites.get_rapid7_text_from_url(rapid7_link['url'])
        functions_tools.print_debug_message("Rapid7 query: " + query)
        functions_tools.print_debug_message("Rapid7 url found: " + rapid7_link['url'])
        functions_tools.print_debug_message("=== Rapid7 text ===")
        functions_tools.print_debug_message(rapid7_text)
        functions_tools.print_debug_message("=== End of Rapid7 text ===")
        comments['rapid7'] = rapid7_text

    if "ZDI" in comments_links:
        zdi_link = comments_links["ZDI"]
    else:
        queries = [
            "site:https://www.zerodayinitiative.com/blog THE " + month + " " + year + " SECURITY UPDATE REVIEW",
            "site:https://www.thezdi.com/blog Microsoft Patches for " + month + " " + year
        ]
        zdi_link = functions_source_analytic_sites.get_duckduckgo_search_results_multiple_queries(queries)
    # zdi_link = {'title':'THE SEPTEMBER 2021 SECURITY UPDATE REVIEW',
    #             'url':'https://www.zerodayinitiative.com/blog/2021/9/14/the-september-2021-security-update-review-kpgpb'}
    if zdi_link:
        zdi_text = functions_source_analytic_sites.get_zdi_text_from_url(zdi_link['url'])
        functions_tools.print_debug_message("ZDI query: " + query)
        functions_tools.print_debug_message("ZDI url found: " + zdi_link['url'])
        functions_tools.print_debug_message("=== ZDI text ===")
        functions_tools.print_debug_message(zdi_text)
        functions_tools.print_debug_message("=== End of ZDI text ===")
        comments['zdi'] = zdi_text

    for source in comments_links.keys():
        if source not in ['Qualys', 'Rapid7', 'Tenable', 'ZDI']:
            text = functions_source_analytic_sites.get_text_from_url(comments_links[source]['url'])
            functions_tools.print_debug_message(source + " url found: " + comments_links[source]['url'])
            functions_tools.print_debug_message("=== " + source + " text ===")
            functions_tools.print_debug_message(text)
            functions_tools.print_debug_message("=== End of " + source + " text ===")
            comments[source.lower()] = text

    report_id = month + " " + year
    report_name = 'Microsoft Patch Tuesday, ' + month + " " + year
    file_name_prefix = "ms_patch_tuesday_" + month.lower() + year
    cves_text = ms_cves

    data_sources = None  # Use all data sources
    file_path = "data/profiles/" + file_name
    products_text = ""
    functions_profile.save_profile(file_path, report_id, report_name, file_name_prefix,
                                   cves_text, products_text, data_sources, comments)


