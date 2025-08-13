DEST="/root/app/sbom_web_app/data"
ssh root@143.244.146.89 "mkdir -p $DEST"

rsync -avhP \
  libraries_with_detailed_vulnerability_status.csv \
  MAIN_global2000_complete.csv \
  repos_with_zero_libraries.csv \
  repositories_summary_with_zero_libs.csv \
  vulnerability_summary.csv \
  root@143.244.146.89:"$DEST/"