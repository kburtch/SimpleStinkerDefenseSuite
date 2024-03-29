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

TL="$WEBROOT""/""top_logins.frag"
DS="$WEBROOT""/""daily_summary.frag"
TC="$WEBROOT""/""top_countries.frag"

FILTER_LIST="data/report_filter.txt"

LOG_LINES=0
ERR_LINES=0
OK_LINES=0

SPAR_CMD="/usr/local/bin/spar"
XVFB_RUN_CMD="/usr/bin/xvfb-run"

# Look at the last two log files.  Assemble entries for today or yesterday
# only.  Add up the number of errors.  This assumes the report runs close
# to midnight so there are few entries for today.

LOG_FILES=`ls -t log/blocker.log* | head -2`

echo "$LOG_FILES" | { while read LOG_FILE ; do
  TMP=`fgrep "$REPORT_DATE_TODAY" "$LOG_FILE" | wc -l`
  let "LOG_LINES=LOG_LINES+TMP"
  TMP=`fgrep "$REPORT_DATE_YESTERDAY" "$LOG_FILE" | wc -l`
  let "LOG_LINES=LOG_LINES+TMP"
  TMP=`fgrep "$REPORT_DATE_TODAY" "$LOG_FILE" | fgrep ':ERROR:' | fgrep -v "Nikto" | wc -l`
  let "ERR_LINES=ERR_LINES+TMP"
  TMP=`fgrep "$REPORT_DATE_YESTERDAY" "$LOG_FILE" | fgrep ':ERROR:' | fgrep -v "Nikto" | wc -l`
  let "ERR_LINES=ERR_LINES+TMP"
  TMP=`fgrep "$REPORT_DATE_TODAY" "$LOG_FILE" | fgrep ':OK' | wc -l`
  let "OK_LINES=OK_LINES+TMP"
  TMP=`fgrep "$REPORT_DATE_YESTERDAY" "$LOG_FILE" | fgrep ':OK' | wc -l`
  let "OK_LINES=OK_LINES+TMP"
  echo "$LOG_LINES" > "$TMP1"
  echo "$ERR_LINES" > "$TMP2"
  echo "$OK_LINES" > "$TMP3"
done }
LOG_LINES=`cat "$TMP1"`
ERR_LINES=`cat "$TMP2"`
OK_LINES=`cat "$TMP3"`
rm "$TMP1"
rm "$TMP2"
rm "$TMP3"

# LOG_LINES=`fgrep "$REPORT_DATE" log/blocker.log | wc -l`
# ERR_LINES=`fgrep "$REPORT_DATE" log/blocker.log | fgrep ':ERROR:' | fgrep -v "Nickto" | wc -l`
# OK_LINES=`fgrep "$REPORT_DATE" log/blocker.log | fgrep ':OK' | wc -l`

echo "Report Date: $REPORT_DATE_YESTERDAY"
echo
echo "Errors: $ERR_LINES"
echo "OK:     $OK_LINES"
echo "Total:  $LOG_LINES lines"
echo

# Show the errors reported for yesterday and the beginning of today only.

echo "Errors"
echo
echo "$LOG_FILES" | { while read LOG_FILE ; do
  fgrep "$REPORT_DATE_YESTERDAY" "$LOG_FILE" | fgrep ':ERROR:' | fgrep -v "Nikto"
  fgrep "$REPORT_DATE_TODAY" "$LOG_FILE" | fgrep ':ERROR:' | fgrep -v "Nikto"
done }
echo
echo "Reports"
echo

# Get all the summary reports from the blockers.  They all contain "process".
echo "$LOG_FILES" | { while read LOG_FILE ; do
   fgrep "$REPORT_DATE_YESTERDAY" < "$LOG_FILE" | fgrep ':OK' | fgrep "Process" >> "t.t.$$"
   fgrep "$REPORT_DATE_TODAY" < "$LOG_FILE" | fgrep ':OK' | fgrep "Process" >> "t.t.$$"
done }
TMP=`cat "t.t.$$"`
rm "t.t.$$"
echo "$TMP"

# To avoid double-counting some summary reports, record and filter out
# ones we've already seen and reported on.

if [ -z "$DRY_RUN" ] ; then
   if [ -f "$FILTER_LIST" ] ; then
      TMP=`echo "$TMP" | fgrep -v -f "$FILTER_LIST"`
   fi
   # Save the new set of filters so we don't double-count
   if [ -n "$TMP" ] ; then
      echo "$TMP" > "$FILTER_LIST"
   elif [ -f "$FILTER_LIST" ] ; then
      rm "$FILTER_LIST"
   fi
fi

# Separate the reports by blocker.
# With the summary records, there may be multiple records since once is
# generated should the blockers be stopped.

HTTP_SUMMARY=`echo "$TMP" | fgrep "http_blocker"`
SSH_SUMMARY=`echo "$TMP" | fgrep "sshd_blocker"`
MAIL_SUMMARY=`echo "$TMP" | fgrep "mail_blocker"`

HTTP_EVENTS=0
TMP=`echo "$HTTP_SUMMARY" | cut -d\; -f2 | cut -d= -f2 | tr -d ' '`
HTTP_EVENTS=`echo "$TMP" | paste -sd+ | bc`
if [ "$HTTP_EVENTS" = "" ] ; then
   HTTP_EVENTS=0
fi

SSH_NEW=0
TMP=`echo "$SSH_SUMMARY" | cut -d\; -f2 | cut -d= -f2 | tr -d ' '`
SSH_NEW=`echo "$TMP" | paste -sd+ | bc`
if [ "$SSH_NEW" = "" ] ; then
   SSH_NEW=0
fi

SSH_OLD=0
TMP=`echo "$SSH_SUMMARY" | cut -d\; -f4 | cut -d= -f2 | tr -d ' '`
SSH_OLD=`echo "$TMP" | paste -sd+ | bc`
if [ "$SSH_OLD" = "" ] ; then
   SSH_OLD=0
fi

let "SSH_EVENTS=SSH_NEW+SSH_OLD"

MAIL_EVENTS=0
TMP=`echo "$MAIL_SUMMARY" | cut -d\; -f2 | cut -d= -f2 | tr -d ' '`
MAIL_EVENTS=`echo "$TMP" | paste -sd+ | bc`
if [ "$MAIL_EVENTS" = "" ] ; then
   MAIL_EVENTS=0
fi

# For spam events, older log entries do not have the spam line item.
# We will process it the slow way without paste/bc.

SPAM_EVENTS=0
echo "$MAIL_SUMMARY" | ( while read LINE ; do
   TMP=`echo "$LINE" | cut -d\; -f3 | cut -d= -f2 | tr -d ' '`
   if [ "$TMP" != "" ] ; then
      let "SPAM_EVENTS=SPAM_EVENTS+TMP"
   fi
done
echo "$SPAM_EVENTS" > "t.t.$$"
)
SPAM_EVENTS=`cat "t.t.$$"`
rm "t.t.$$"

#TMP=`echo "$MAIL_SUMMARY" | cut -d\; -f3 | cut -d= -f2 | tr -d ' '`
#SPAM_EVENTS=`echo "$TMP" | paste -sd+ | bc`

# For the ipset block list, there's 8 lines of headers

CURRENT_BLOCKS=`/sbin/ipset -L blocklist  | wc -l`
let "CURRENT_BLOCKS=CURRENT_BLOCKS-8"

# Dump the blocked list.

# TODO: not blocked.out, write a specific script to do this without the overhead
# This can take a long time and generate a lot of data.

# TODO: Total on file is calculated by the wash and could be saved

#NEEDED=1
#if [ -n "$DRY_RUN" ] ; then
#   if [ -f "$TMP_BLK" ] ; then
#      NEEDED=
#   fi
#fi
#if [ -n "$NEEDED" ] ; then
#   /usr/local/bin/spar -m list_blocked.sp > "$TMP_BLK"
#fi
#COUNTRY_SUMMARY=`fgrep Country < "$TMP_BLK" | cut -d: -f2 | sort | uniq -c | sort -rn | head -30`
#if [ -z "$DRY_RUN" ] ; then
#   rm "$TMP_BLK"
#fi

# From the wash_blocked task.

COUNTRY_SUMMARY=`sort -nr data/country_cnt.txt | head -n 30`
TOTAL_ON_FILE=`cat /root/ssds/data/blocking_cnt.txt`
TOTAL_LOGINS=`cat /root/ssds/data/login_cnt.txt`
DISK_USAGE=`du -sh data | cut -f1`

# Chart the trend.

if [ -z "$DRY_RUN" ] ; then
   # These variables are required for xvfb-run
   if [ -z "$TMPDIR" ] ; then
      export TMPDIR="/tmp"
   fi
   if [ -z "$COLUMNS" ] ; then
      export COLUMNS=80
   fi
   # TODO: should not be hard-coded path.  here for debugging
   # TODO: crashing on Red Hat
   #"$XVFB_RUN_CMD" -s "-screen 0 1024x768x16" "$SPAR_CMD" -x graph_series.sp "threat_trend" $HTTP_EVENTS $SSH_EVENTS $MAIL_EVENTS $SPAM_EVENTS >> /root/ssds/nohup.out 2>&1
  #STATUS=$?
  #if [ $STATUS -ne 0 ] ; then
  #   echo "xvfb-run returned status code $STATUS" >> /root/ssds/nohup.out
  #fi
   #bash graph_series.sh "threat_trend" $HTTP_EVENTS $SSH_EVENTS $MAIL_EVENTS $SPAM_EVENTS
fi

# Dump the logins.

TOP_LOGINS=`/usr/local/bin/spar -m list_logins.sp | sort -nr -k1 | fgrep -v "logins:" | head -n 30`
echo "$TOP_LOGINS" > "$TL"

# Firewall Summary:

# Determine time running.

START_TIME=`stat run/sshd_tail_pids | fgrep Change | cut -d: -f2-3`
START_TIME=`date '+%s' --date="$START_TIME"`
CURRENT_TIME=`date '+%s'`
let UPTIME_SECS=CURRENT_TIME-START_TIME
let UPTIME_DAYS=UPTIME_SECS/60 # Minutes
let UPTIME_DAYS=UPTIME_DAYS/60 # Hours
let UPTIME_DAYS=UPTIME_DAYS/24 # Days

echo '<div class="kpi_box">' > "$DS"
echo '<div class="kpi_header">'"<b>Yesterday's Activity</b></div>" >> "$DS"
echo '<div style="width:100%; height: 100%">' >> "$DS"
echo '<table style="border: none; padding: 0; border-collapse: collapse; margin: 0 auto">' >> "$DS"

ERROR_LIMIT=`/usr/local/bin/spar utils/export_error_limit.sp`
BGCOLOR="background-color: transparent"
if [ $ERR_LINES -ge "$ERROR_LIMIT" ] ; then
   BGCOLOR="background-color: red"
   /usr/local/bin/spar utils/error_limit.sp
fi

echo "<tr>" >> "$DS"
echo '<td class="kpi_layout"><span class="plain_data" style="'"$BGCOLOR"'">'"$ERR_LINES""</span>""</td><td>"'<span class="plain_light">'" Errors""</span>""</td>" >> "$DS" 
echo "</tr><tr>" >> "$DS"
echo '<td class="kpi_layout"><span class="plain_data">'"$OK_LINES""</span>""</td><td>"'<span class="plain_light">'" Status Reports""</span>""</td>" >> "$DS"
echo "</tr><tr>" >> "$DS"
echo '<td class="kpi_layout"><span class="plain_data">'"$LOG_LINES""</span>""</td><td>"'<span class="plain_light">'" SSDS Log Lines""</span>""</td>" >> "$DS"
echo "</tr><tr>" >> "$DS"
echo '<td class="kpi_layout"><span class="plain_data">'"$UPTIME_DAYS""</span>""</td><td>"'<span class="plain_light">'" Days Up""</span>""</td>" >> "$DS"
echo "</tr>" >> "$DS"
echo "</table>" >> "$DS"
echo "</div>" >> "$DS"
echo "</div>" >> "$DS"

echo >> "$DS"
echo '<div class="kpi_box">' >> "$DS"
echo '<div class="kpi_header">'"<b>Yesterday's Blocks</b></div>" >> "$DS"
echo '<div style="width:100%; height: 100%">' >> "$DS"
echo '<table style="border: none; padding: 0; border-collapse: collapse; margin:0 auto">' >> "$DS"

HTTP_LIMIT=`/usr/local/bin/spar utils/export_http_limit.sp`
BGCOLOR="background-color: transparent"
if [ "$HTTP_EVENTS" -ge "$HTTP_LIMIT" ] ; then
   BGCOLOR="background-color: darkred"
   /usr/local/bin/spar utils/http_limit.sp "$HTTP_EVENTS"
fi

echo "<tr>" >> "$DS"
echo '<td class="kpi_layout"><span class="plain_data" style="color: red; '"$BGCOLOR"'" text-align="right">'"$HTTP_EVENTS""</span>""</td><td>"'<span class="plain_light">'" for Web""</span>""</td>" >> "$DS"
echo "</tr><tr>" >> "$DS"

SSHD_LIMIT=`/usr/local/bin/spar utils/export_sshd_limit.sp`
BGCOLOR="background-color: transparent"
if [ $SSH_EVENTS -ge "$SSHD_LIMIT" ] ; then
   BGCOLOR="background-color: red"
   /usr/local/bin/spar utils/sshd_limit.sp "$SSH_EVENTS"
fi

echo '<td class="kpi_layout"><span class="plain_data" style="color: green; '"$BGCOLOR"'" text-align="right">'"$SSH_EVENTS""</span>""</td><td>"'<span class="plain_light">'" for Login""</span>""</td>" >> "$DS"
echo "</tr><tr>" >> "$DS"

MAIL_LIMIT=`/usr/local/bin/spar utils/export_mail_limit.sp`
BGCOLOR="background-color: transparent"
if [ "$MAIL_EVENTS" -ge "$MAIL_LIMIT" ] ; then
   BGCOLOR="background-color: red"
   /usr/local/bin/spar utils/mail_limit.sp "$MAIL_EVENTS"
fi
echo '<td class="kpi_layout"><span class="plain_data" style="color: blue; '"$BGCOLOR"'" text-align="right">'"$MAIL_EVENTS""</span>""</td><td>"'<span class="plain_light">'" for Mail""</span>""</td>" >> "$DS"
echo "</tr><tr>" >> "$DS"

SPAM_LIMIT=`/usr/local/bin/spar utils/export_spam_limit.sp`
BGCOLOR="background-color: transparent"
if [ $SPAM_EVENTS -ge "$SPAM_LIMIT" ] ; then
   BGCOLOR="background-color: red"
   /usr/local/bin/spar utils/spam_limit.sp "$SPAM_EVENTS"
fi

echo '<td class="kpi_layout"><span class="plain_data" style="color: goldenrod; '"$BGCOLOR"'" text-align="right">'"$SPAM_EVENTS""</span>""</td><td>"'<span class="plain_light">'" for Spam""</span>""</td>" >> "$DS"
echo "</tr>" >> "$DS"
echo "</table>" >> "$DS"
echo "</div>" >> "$DS"
echo "</div>" >> "$DS"

BGCOLOR="background-color: transparent"
if [ "$CURRENT_BLOCKS" -gt 25000 ] ; then
   BGCOLOR="background-color: red"
elif [ "$CURRENT_BLOCKS" -gt 12000 ] ; then
   BGCOLOR="background-color: orange"
elif [ "$CURRENT_BLOCKS" -eq 0 ] ; then
   BGCOLOR="background-color: red"
fi

# By Country

echo "$COUNTRY_SUMMARY" > "$TC"

# Hourly

bash report_hourly.sh

