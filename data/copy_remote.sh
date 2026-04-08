DEST="/home/dima/sbom_web_app/data"
ssh dima@10.20.5.21 "mkdir -p $DEST"

rsync -avhP \
  libraries_with_detailed_vulnerability_status.csv \
  MAIN_global2000_complete.csv \
  repos_with_zero_libraries.csv \
  repositories_summary_with_zero_libs.csv \
  vulnerability_summary.csv \
  libraries_with_detailed_vulnerability_status.csv \
  dima@10.20.5.21:"$DEST/"
