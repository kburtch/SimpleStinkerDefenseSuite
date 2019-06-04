#!/bin/bash
#
# Daily Report
# by Ken O. Burtch
# Produce the daily email report as well as update the web dashboard.
#############################################################################

# If a non-empty string, runs the report for testing.

DRY_RUN=

# The location of the web dashboard.

WEBROOT="/var/www/html/pegasoft/ssds"

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
   bash graph_series.sh "threat_trend" $HTTP_EVENTS $SSH_EVENTS $MAIL_EVENTS $SPAM_EVENTS
fi

# Dump the logins.

TOP_LOGINS=`/usr/local/bin/spar -m list_logins.sp | sort -nr -k2 | fgrep -v "logins:" | head -n 30`
echo "$TOP_LOGINS" > "$TL"

# Daily Summary:

echo '<div style="background-color: whitesmoke; padding: 0 10px 0 10px">' > "$DS"
echo "<p><b>Log Summary</b></p>" >> "$DS"
echo '<table style="border: none; padding: none; border-collapse: collapse>"' >> "$DS"

BGCOLOR="background-color: none"
if [ $ERR_LINES -ge 60 ] ; then
   BGCOLOR="background-color: red"
fi

echo "<tr>" >> "$DS"
echo '<td style="text-align:right; min-width: 50px; padding-right:3px">''<span style="'"$BGCOLOR"'">'"$ERR_LINES""</span>""</td><td>""<span>"" Errors""</span>""</td>" >> "$DS" 
echo "</tr><tr>" >> "$DS"
echo '<td style="text-align:right; min-width: 50px; padding-right:3px">''<span>'"$OK_LINES""</span>""</td><td>""<span>"" Reports (OK)""</span>""</td>" >> "$DS"
echo "</tr><tr>" >> "$DS"
echo '<td style="text-align:right; min-width: 50px; padding-right:3px">''<span>'"$LOG_LINES""</span>""</td><td>""<span>"" Lines""</span>""</td>" >> "$DS"
echo "</tr>" >> "$DS"
echo "</table>" >> "$DS"
echo "</div>" >> "$DS"

echo >> "$DS"
echo '<div style="background-color: whitesmoke; padding: 0 5px 0 5 px">' >> "$DS"
echo "<p><b>Yesterday's Blocks</b></p>" >> "$DS"
echo '<table style="border: none; padding: none; border-collapse: collapse">' >> "$DS"
echo "<tr>" >> "$DS"
echo '<td style="text-align:right; min-width: 50px; padding-right:3px">''<span style="color: red" align="right">'"$HTTP_EVENTS""</span>""</td><td>""<span>"" for Web""</span>""</td>" >> "$DS"
echo "</tr><tr>" >> "$DS"
echo '<td style="text-align:right; min-width: 50px; padding-right:3px">''<span style="color: green" align="right">'"$SSH_EVENTS""</span>""</td><td>""<span>"" for Login""</span>""</td>" >> "$DS"
echo "</tr><tr>" >> "$DS"
echo '<td style="text-align:right; min-width: 50px; padding-right:3px">''<span style="color: blue" align="right">'"$MAIL_EVENTS""</span>""</td><td>""<span>"" for Mail""</span>""</td>" >> "$DS"
echo "</tr><tr>" >> "$DS"
echo '<td style="text-align:right; min-width: 50px; padding-right:3px">''<span style="color: goldenrod" align="right">'"$SPAM_EVENTS""</span>""</td><td>""<span>"" for Spam""</span>""</td>" >> "$DS"
echo "</tr>" >> "$DS"
echo "</table>" >> "$DS"
echo "</div>" >> "$DS"

BGCOLOR="background-color: none"
if [ "$CURRENT_BLOCKS" -gt 25000 ] ; then
   BGCOLOR="background-color: red"
elif [ "$CURRENT_BLOCKS" -gt 12000 ] ; then
   BGCOLOR="background-color: orange"
elif [ "$CURRENT_BLOCKS" -eq 0 ] ; then
   BGCOLOR="background-color: red"
fi

# TODO: this could be monitored by the hourly task
echo >> "$DS"
echo '<div style="background-color: whitesmoke; padding: 0 5px 0 5 px">' >> "$DS"
echo "<p><b>Midnight Snapshot</b></p>" >> "$DS"
echo '<table style="border: none; padding: none; border-collapse: collapse">' >> "$DS"
echo "<tr>" >> "$DS"
echo '<td style="text-align:right; min-width: 50px; padding-right:3px">''<span style="'"$BGCOLOR"'">'"$CURRENT_BLOCKS""</span>""</td><td>""<span>"" Actively Blocked""</span>""</td>" >> "$DS"
echo "</tr><tr>" >> "$DS"
echo '<td style="text-align:right; min-width: 50px; padding-right: 3px;">''<span>'"$TOTAL_ON_FILE""</span>""</td><td>""<span>"" Monitored""</span>""</td>" >> "$DS"
echo "</tr><tr>" >> "$DS"
echo '<td style="text-align:right; min-width: 50px; padding-right: 3px;">''<span>'"$TOTAL_LOGINS""</span>""</td><td>""<span>""Usernames Known""</span>""</td>" >> "$DS"
echo "</tr><tr>" >> "$DS"
echo '<td style="text-align:right; min-width: 50px; padding-right: 3px;">''<span>'"$DISK_USAGE""</span>""</td><td>""<span>""Used""</span>""</td>" >> "$DS"
echo "</tr>" >> "$DS"
echo "</table>" >> "$DS"
echo "</div>" >> "$DS"

# By Country

echo "$COUNTRY_SUMMARY" > "$TC"

