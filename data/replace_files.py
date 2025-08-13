import os, shutil, sys

sources = [
    "/Users/dmk6603/Documents/forbes_global_2000/5_summaries/output/libraries_with_detailed_vulnerability_status.csv",
    "/Users/dmk6603/Documents/forbes_global_2000/MAIN_global2000_complete.csv",
    "/Users/dmk6603/Documents/forbes_global_2000/5_summaries/output/repos_with_zero_libraries.csv",
    "/Users/dmk6603/Documents/forbes_global_2000/5_summaries/output/repositories_summary_with_zero_libs.csv",
    "/Users/dmk6603/Documents/forbes_global_2000/5_summaries/output/summaries/vulnerability_summary.csv",
]

dest = os.getcwd()

for src in sources:
    if os.path.isfile(src):
        shutil.copy2(src, dest)
        print(f"Copied: {os.path.basename(src)}")
    else:
        print(f"WARNING: not found -> {src}", file=sys.stderr)