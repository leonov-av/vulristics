import functions_profile_ms_patch_tuesday
import functions_tools
import functions_report_vulnerabilities
import os

def make_ms_patch_tuesday_report(year, month, comments_links_path=False, patch_tuesday_date=False, rewrite_flag=False):
    # month = "October"
    # year = "2020"
    if patch_tuesday_date == False:
        patch_tuesday_date = functions_profile_ms_patch_tuesday.get_second_tuesday(year=year, long_month_name=month)
    file_name = "ms_patch_tuesday_" + month.lower() + year + ".json"

    comments_links = dict()
    if comments_links_path:
        f = open(comments_links_path, "r")
        for line in f.read().split("\n"):
            comments_links[line.split("|")[0]] = {'title':line.split("|")[1], 'url':line.split("|")[2]}
        f.close()

    if rewrite_flag or not os.path.isfile("data/profiles/" + file_name):
        functions_tools.print_debug_message("Creating Patch Tuesday profile...")
        functions_profile_ms_patch_tuesday.create_profile(month, year, patch_tuesday_date, comments_links, file_name)

    profile_file_path = "data/profiles/" + file_name
    functions_report_vulnerabilities.make_vulnerability_report_for_profile(profile_file_path, rewrite_flag)