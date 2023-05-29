from vulristics_code import functions_report_ms_patch_tuesday

year = "2021"
months = list()
months.append("September")

rewrite_flag = True
#rewrite_flag = False

for month in months:
    functions_report_ms_patch_tuesday.make_ms_patch_tuesday_report(pt_type="Normal",
                                                                   year=year,
                                                                   month=month,
                                                                   rewrite_flag=rewrite_flag)
