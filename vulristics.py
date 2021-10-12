import functions_report_ms_patch_tuesday
import argparse

parser = argparse.ArgumentParser(description='Simple password manager')
const = ""
parser.add_argument('--report-type', help='Report type')
parser.add_argument('--mspt-year', help='Microsoft Patch Tuesday year')
parser.add_argument('--mspt-month', help='Microsoft Patch Tuesday month')
parser.add_argument('--rewrite-flag', help='Rewrite Flag')

args = parser.parse_args()

if args.report_type == "ms_patch_tuesday":
    year = str(args.mspt_year) # 2021
    month = args.mspt_month # September

    if args.rewrite_flag == "True" or args.rewrite_flag == "true":
        rewrite_flag = True
    else:
        rewrite_flag = False

    functions_report_ms_patch_tuesday.make_ms_patch_tuesday_report(year=year,
                                                                   month=month,
                                                                   rewrite_flag=rewrite_flag)
