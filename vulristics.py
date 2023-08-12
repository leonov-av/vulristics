from vulristics_code import functions_report_vulnerabilities, functions_report_ms_patch_tuesday, functions_profile
import argparse
import re

parser = argparse.ArgumentParser(description='An extensible framework for analyzing publicly available information about vulnerabilities')
const = ""
parser.add_argument('--report-type', help='Report type (ms_patch_tuesday, ms_patch_tuesday_extended or cve_list)')
parser.add_argument('--mspt-year', help='Microsoft Patch Tuesday year')
parser.add_argument('--mspt-month', help='Microsoft Patch Tuesday month')
parser.add_argument('--mspt-comments-links-path', help='Microsoft Patch Tuesday comments links file')
parser.add_argument('--cve-project-name', help='Name of the CVE Project')
parser.add_argument('--cve-list-path', help='Path to the list of CVE IDs')
parser.add_argument('--cve-comments-path', help='Path to the CVE comments file')
parser.add_argument('--cve-data-sources', help='Data sources for analysis, e.g. "ms,nvd,epss,vulners,attackerkb"')


parser.add_argument('--rewrite-flag', help='Rewrite Flag (True/False, Default - False)')
parser.add_argument('--vulners-use-github-exploits-flag', help='Use Vulners Github exploits data Flag (True/False, Default - True)')

args = parser.parse_args()
banner = '''
                      /$$           /$$             /$$     /$$                    
                     | $$          |__/            | $$    |__/                    
 /$$    /$$ /$$   /$$| $$  /$$$$$$  /$$  /$$$$$$$ /$$$$$$   /$$  /$$$$$$$  /$$$$$$$
|  $$  /$$/| $$  | $$| $$ /$$__  $$| $$ /$$_____/|_  $$_/  | $$ /$$_____/ /$$_____/
 \  $$/$$/ | $$  | $$| $$| $$  \__/| $$|  $$$$$$   | $$    | $$| $$      |  $$$$$$ 
  \  $$$/  | $$  | $$| $$| $$      | $$ \____  $$  | $$ /$$| $$| $$       \____  $$
   \  $/   |  $$$$$$/| $$| $$      | $$ /$$$$$$$/  |  $$$$/| $$|  $$$$$$$ /$$$$$$$/
    \_/     \______/ |__/|__/      |__/|_______/    \___/  |__/ \_______/|_______/ '''

print(re.sub("^\n","",banner))

source_config = dict()

source_config['rewrite_flag'] = False
if args.rewrite_flag == "True" or args.rewrite_flag == "true":
    source_config['rewrite_flag'] = True

source_config['vulners_use_github_exploits_flag'] = True
if args.vulners_use_github_exploits_flag == "False" or args.vulners_use_github_exploits_flag == "false":
    source_config['vulners_use_github_exploits_flag'] = False


print(source_config)

if args.report_type == "ms_patch_tuesday" or args.report_type == "ms_patch_tuesday_extended":
    year = str(args.mspt_year) # 2021
    month = args.mspt_month # September


    comments_links_path = False
    if args.mspt_comments_links_path:
        comments_links_path = args.mspt_comments_links_path

    if args.report_type == "ms_patch_tuesday":
        pt_type = "Normal"
    elif args.report_type == "ms_patch_tuesday_extended":
        pt_type = "Extended"

    functions_report_ms_patch_tuesday.make_ms_patch_tuesday_report(pt_type=pt_type,
                                                                   year=year,
                                                                   month=month,
                                                                   comments_links_path = comments_links_path,
                                                                   source_config=source_config)
elif args.report_type == "cve_list":

    name = args.cve_project_name
    report_name = name + ' report'
    file_name_prefix = re.sub(" ","_",name).lower()

    cve_list_text = ""
    with open(args.cve_list_path, 'r') as file:
        cve_list_text = file.read()

    comments = dict()
    if args.cve_comments_path:
        with open(args.cve_comments_path, 'r') as file:
            cve_comments_text = file.read()
            if cve_comments_text != "":
                for line in cve_comments_text.split("\n"):
                    if "|" in line:
                        group = line.split("|")[0]
                        line = re.sub("[^\|]*\|","",line)
                    else:
                        group = "Comment"
                    if not group in comments:
                        comments[group] = ""
                    comments[group] += line + "\n"

    # with open('analyze_product_list.txt', 'r') as file:
    #     products_text = file.read()
    products_text = ""

    file_name = name + "_profile.json"
    report_id = name + "_report"
    data_sources = args.cve_data_sources.split(",")


    profile_file_path = "data/profiles/" + file_name
    functions_profile.save_profile(profile_file_path=profile_file_path,
                                   report_id=report_id,
                                   report_name=report_name,
                                   file_name_prefix=file_name_prefix,
                                   cve_list_text=cve_list_text,
                                   products_text=products_text,
                                   data_sources=data_sources,
                                   comments=comments)
    functions_report_vulnerabilities.make_vulnerability_report_for_profile(profile_file_path=profile_file_path,
                                                                           source_config=source_config)

