import functions_profile
import functions_report_vulnerabilities
import functions_report_ms_patch_tuesday
import argparse
import re

parser = argparse.ArgumentParser(description='An extensible framework for analyzing publicly available information about vulnerabilities')
const = ""
parser.add_argument('--report-type', help='Report type')
parser.add_argument('--mspt-year', help='Microsoft Patch Tuesday year')
parser.add_argument('--mspt-month', help='Microsoft Patch Tuesday month')
parser.add_argument('--mspt-comments-links-path', help='Microsoft Patch Tuesday comments links file')
parser.add_argument('--cve-project-name', help='Name of the CVE Project')
parser.add_argument('--cve-list-path', help='Path to the list of CVE IDs')
parser.add_argument('--cve-comments-path', help='Path to the CVE comments file')
parser.add_argument('--cve-data-sources', help='Data sources for analysis, e.g. "ms,nvd,vulners,attackerkb"')


parser.add_argument('--rewrite-flag', help='Rewrite Flag')

args = parser.parse_args()

print('''                      /$$           /$$             /$$     /$$                    
                     | $$          |__/            | $$    |__/                    
 /$$    /$$ /$$   /$$| $$  /$$$$$$  /$$  /$$$$$$$ /$$$$$$   /$$  /$$$$$$$  /$$$$$$$
|  $$  /$$/| $$  | $$| $$ /$$__  $$| $$ /$$_____/|_  $$_/  | $$ /$$_____/ /$$_____/
 \  $$/$$/ | $$  | $$| $$| $$  \__/| $$|  $$$$$$   | $$    | $$| $$      |  $$$$$$ 
  \  $$$/  | $$  | $$| $$| $$      | $$ \____  $$  | $$ /$$| $$| $$       \____  $$
   \  $/   |  $$$$$$/| $$| $$      | $$ /$$$$$$$/  |  $$$$/| $$|  $$$$$$$ /$$$$$$$/
    \_/     \______/ |__/|__/      |__/|_______/    \___/  |__/ \_______/|_______/ ''')

if args.report_type == "ms_patch_tuesday":
    year = str(args.mspt_year) # 2021
    month = args.mspt_month # September

    if args.rewrite_flag == "True" or args.rewrite_flag == "true":
        rewrite_flag = True
    else:
        rewrite_flag = False

    comments_links_path = False
    if args.mspt_comments_links_path:
        comments_links_path = args.mspt_comments_links_path

    functions_report_ms_patch_tuesday.make_ms_patch_tuesday_report(year=year,
                                                                   month=month,
                                                                   comments_links_path = comments_links_path,
                                                                   rewrite_flag=rewrite_flag)
elif args.report_type == "cve_list":
    if args.rewrite_flag == "True" or args.rewrite_flag == "true":
        rewrite_flag = True
    else:
        rewrite_flag = False

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
    functions_profile.save_profile(profile_file_path, report_id, report_name, file_name_prefix, cve_list_text,
                                   products_text,
                                   data_sources, comments)
    functions_report_vulnerabilities.make_vulnerability_report_for_profile(profile_file_path, rewrite_flag)

