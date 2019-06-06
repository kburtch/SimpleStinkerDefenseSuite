#!/bin/bash
#
# Daily Report
# by Ken O. Burtch
# Produce the daily email report as well as update the web dashboard.
#############################################################################

# If a non-empty string, runs the report for testing.

DRY_RUN=

# The location of the web dashboard.

cd "utils"
WEBROOT=`/usr/local/bin/spar export_dashboard_file_path.sp`
if [ -z "$WEBROOT" ] ; then
   echo "Could not lookup web dashboard location" 2>&1
   exit 1
fi
cd ..

# Yesterday, and just after midnight today

REPORT_DATE_TODAY=`date '+%m/%d'`" 00:"
REPORT_DATE_YESTERDAY=`date --date 'yesterday' '+%m/%d'`
TMP_DIR="run"
TMP1="$TMP_DIR""/""tmp1.$$"
TMP2="$TMP_DIR""/""tmp2.$$"
TMP3="$TMP_DIR""/""tmp3.$$"
TMP_BLK="$TMP_DIR""/""tmp_blk"

HS="$WEBROOT""/""hourly_summary.frag"

# For the ipset block list, there's 8 lines of headers

CURRENT_BLOCKS=`/sbin/ipset -L blocklist  | wc -l`
let "CURRENT_BLOCKS=CURRENT_BLOCKS-8"
TOTAL_ON_FILE=`cat /root/ssds/data/blocking_cnt.txt`
TOTAL_LOGINS=`cat /root/ssds/data/login_cnt.txt`
DISK_USAGE=`du -sh data | cut -f1`

if [ "$CURRENT_BLOCKS" -gt 25000 ] ; then
   BGCOLOR="background-color: red"
elif [ "$CURRENT_BLOCKS" -gt 12000 ] ; then
   BGCOLOR="background-color: orange"
elif [ "$CURRENT_BLOCKS" -eq 0 ] ; then
   BGCOLOR="background-color: red"
fi

echo > "$HS"
echo '<div style="background-color: whitesmoke; padding: 0 5px 0 5 px">' >> "$HS"
echo "<p><b>Hourly Status</b></p>" >> "$HS"
echo '<table style="border: none; padding: none; border-collapse: collapse">' >> "$HS"
echo "<tr>" >> "$HS"
echo '<td style="text-align:right; min-width: 50px; padding-right:3px">''<span style="'"$BGCOLOR"'">'"$CURRENT_BLOCKS""</span>""</td><td>""<span>"" Actively Blocked""</span>""</td>" >> "$HS"
echo "</tr><tr>" >> "$HS"
echo '<td style="text-align:right; min-width: 50px; padding-right: 3px;">''<span>'"$TOTAL_ON_FILE""</span>""</td><td>""<span>"" Monitored""</span>""</td>" >> "$HS"
echo "</tr><tr>" >> "$HS"
echo '<td style="text-align:right; min-width: 50px; padding-right: 3px;">''<span>'"$TOTAL_LOGINS""</span>""</td><td>""<span>""Usernames""</span>""</td>" >> "$HS"
echo "</tr><tr>" >> "$HS"
echo '<td style="text-align:right; min-width: 50px; padding-right: 3px;">''<span>'"$DISK_USAGE""</span>""</td><td>""<span>""Used""</span>""</td>" >> "$HS"
echo "</tr>" >> "$HS"
echo "</table>" >> "$HS"
echo "</div>" >> "$HS"

