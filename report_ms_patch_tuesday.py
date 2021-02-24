import functions_report_ms_patch_tuesday

# year = "2020"
# months = list()
# months.append("October")
# months.append("November")
# months.append("December")

year = "2021"
months = list()
# months.append("January")
months.append("February")

rewrite_flag = False
# rewrite_flag = False

for month in months:
    functions_report_ms_patch_tuesday.make_ms_patch_tuesday_report(year=year,
                                                                   month=month,
                                                                   rewrite_flag=rewrite_flag)
