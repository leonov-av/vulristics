import functions_profile_ms_patch_tuesday
import functions_tools
import functions_report_vulnerabilities
import os

def make_ms_patch_tuesday_report(pt_type, year, month, comments_links_path=False, patch_tuesday_date=False,
                                 rewrite_flag=False):
    # month = "October"
    # year = "2020"
    pt_related_dates = dict()
    if patch_tuesday_date == False:
        pt_related_dates = functions_profile_ms_patch_tuesday.get_patch_tuesday_related_dates(year=year,
                                                                                              long_month_name=month)
    else:
        pt_related_dates["patch_tuesday"] = patch_tuesday_date


    file_name = "ms_patch_tuesday_" + month.lower() + year + ".json"

    comments_links = dict()
    if comments_links_path:
        f = open(comments_links_path, "r")
        for line in f.read().split("\n"):
            if "|" in line:
                comments_links[line.split("|")[0]] = {'title':line.split("|")[1], 'url':line.split("|")[2]}
        f.close()

    if rewrite_flag or not os.path.isfile("data/profiles/" + file_name):
        functions_tools.print_debug_message("Creating Patch Tuesday profile...")
        functions_profile_ms_patch_tuesday.create_profile(pt_type, month, year, pt_related_dates,
                                                          comments_links, file_name)

    profile_file_path = "data/profiles/" + file_name
    functions_report_vulnerabilities.make_vulnerability_report_for_profile(profile_file_path, rewrite_flag)