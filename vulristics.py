from vulristics_code import functions_report_vulnerabilities, functions_report_ms_patch_tuesday, functions_profile
import argparse
import re

current_version = "1.0.10"

parser = argparse.ArgumentParser(description='An extensible framework for analyzing publicly available information about vulnerabilities')
const = ""

parser.add_argument('--report-type', help='Report type (ms_patch_tuesday, ms_patch_tuesday_extended, cve_list or custom_profile)')
parser.add_argument('--mspt-year', help='Microsoft Patch Tuesday year')
parser.add_argument('--mspt-month', help='Microsoft Patch Tuesday month')
parser.add_argument('--mspt-comments-links-path', help='Microsoft Patch Tuesday comments links file. Format: "Qualys|Description|URL"')
parser.add_argument('--cve-project-name', help='Name of the CVE Project')
parser.add_argument('--cve-list-path', help='Path to the list of CVE IDs (each per line)')
parser.add_argument('--cve-comments-path', help='Path to the CVE comments file')
parser.add_argument('--cve-data-sources', help='Data sources for analysis, e.g. "ms,nvd,bdu,epss,vulners,attackerkb,bdu,custom"')
parser.add_argument('--profile-json-path', help='Custom profile for analysis')
parser.add_argument('--result-formats', help='Result formats, e.g. "html,json", Default - "html"')
parser.add_argument('--result-html-path', help='Path to the results file in html format (Default - will be created in reports directory)')
parser.add_argument('--result-html-label', help='Additional optional banner for HTML report ("lpw" for the Linux Patch Wednesday banner, "mspt" for the Microsoft Patch Tuesday banner or custom image URL)')
parser.add_argument('--result-json-path', help='Path to the results file in json format')
parser.add_argument('--rewrite-flag', help='Rewrite Flag (True/False, Default - False)')
parser.add_argument('--vulners-use-github-exploits-flag', help='Use Vulners Github exploits data Flag (True/False, Default - True)')
parser.add_argument('--bdu-use-product-names-flag', help='Use BDU product names Flag (True/False, Default - True)')
parser.add_argument('--bdu-use-vulnerability-descriptions-flag', help='Use BDU vulnerability descriptions data Flag (True/False, Default - True)')
parser.add_argument('-v', '--version', action='version', version=current_version)

args = parser.parse_args()
banner = r'''
                      /$$           /$$             /$$     /$$                    
                     | $$          |__/            | $$    |__/                    
 /$$    /$$ /$$   /$$| $$  /$$$$$$  /$$  /$$$$$$$ /$$$$$$   /$$  /$$$$$$$  /$$$$$$$
|  $$  /$$/| $$  | $$| $$ /$$__  $$| $$ /$$_____/|_  $$_/  | $$ /$$_____/ /$$_____/
 \  $$/$$/ | $$  | $$| $$| $$  \__/| $$|  $$$$$$   | $$    | $$| $$      |  $$$$$$ 
  \  $$$/  | $$  | $$| $$| $$      | $$ \____  $$  | $$ /$$| $$| $$       \____  $$
   \  $/   |  $$$$$$/| $$| $$      | $$ /$$$$$$$/  |  $$$$/| $$|  $$$$$$$ /$$$$$$$/
    \_/     \______/ |__/|__/      |__/|_______/    \___/  |__/ \_______/|_______/ '''

print("\n", re.sub("^\n","",banner), "\n")

source_config = dict()

source_config['rewrite_flag'] = False
if args.rewrite_flag == "True" or args.rewrite_flag == "true":
    source_config['rewrite_flag'] = True

source_config['vulners_use_github_exploits_flag'] = True
if args.vulners_use_github_exploits_flag == "False" or args.vulners_use_github_exploits_flag == "false":
    source_config['vulners_use_github_exploits_flag'] = False

source_config['bdu_use_product_names_flag'] = True
if args.bdu_use_product_names_flag == "False" or args.bdu_use_product_names_flag == "false":
    source_config['bdu_use_product_names_flag'] = False

source_config['bdu_use_vulnerability_descriptions_flag'] = True
if args.bdu_use_vulnerability_descriptions_flag == "False" or args.bdu_use_vulnerability_descriptions_flag == "false":
    source_config['bdu_use_vulnerability_descriptions_flag'] = False

source_config['data_sources'] = []
if args.cve_data_sources:
    source_config['data_sources'] = args.cve_data_sources.split(",")

result_config = dict()

if args.result_formats:
    result_config['result_formats'] = set(args.result_formats.split(","))
else:
    result_config['result_formats'] = {'html'}

if args.result_json_path:
    result_config['result_json_path'] = args.result_json_path
    result_config['result_formats'].add('json')
else:
    result_config['result_json_path'] = False

if args.result_html_path:
    result_config['result_html_path'] = args.result_html_path
    result_config['result_formats'].add('html')
else:
    result_config['result_html_path'] = False

if args.result_html_label:
    result_config['result_html_label'] = args.result_html_label
else:
    result_config['result_html_label'] = False

if args.report_type == "ms_patch_tuesday" or args.report_type == "ms_patch_tuesday_extended":
    year = str(args.mspt_year) # 2021
    month = args.mspt_month # September
    if not result_config['result_html_label']:
        result_config['result_html_label'] = "mspt"

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
                                                                   source_config=source_config,
                                                                   result_config=result_config)
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
                        line = re.sub(r"[^\|]*\|","",line)
                    else:
                        group = "Comment"
                    if not group in comments:
                        comments[group] = ""
                    comments[group] += line + "\n"

    products_text = ""

    file_name = name + "_profile.json"
    report_id = name + "_report"

    profile_file_path = "data/profiles/" + file_name
    functions_profile.save_profile(profile_file_path=profile_file_path,
                                   report_id=report_id,
                                   report_name=report_name,
                                   file_name_prefix=file_name_prefix,
                                   cve_list_text=cve_list_text,
                                   products_text=products_text,
                                   data_sources=source_config['data_sources'],
                                   comments=comments)
    functions_report_vulnerabilities.make_vulnerability_report_for_profile(profile_file_path=profile_file_path,
                                                                           source_config=source_config,
                                                                           result_config=result_config)

elif args.report_type == "custom_profile":
    functions_report_vulnerabilities.make_vulnerability_report_for_profile(profile_file_path=args.profile_json_path,
                                                                           source_config=source_config,
                                                                           result_config=result_config)
else:
    parser.print_help()
    print('\nExamples:\n$ python3 vulristics.py --report-type "cve_list" --cve-project-name "New Project" --cve-list-path "cves.txt"\n$ python3 vulristics.py --report-type "ms_patch_tuesday" --mspt-year 2024 --mspt-month "August" --rewrite-flag "True"')
