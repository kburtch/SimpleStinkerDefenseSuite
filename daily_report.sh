#!/bin/bash

# Yesterday, and just after midnight today

#REPORT_DATE_TODAY=`date '+%b %e'`" 00:"
REPORT_DATE_TODAY=`date '+%m/%d'`" 00:"
REPORT_DATE_YESTERDAY=`date --date 'yesterday' '+%m/%d'`

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
  echo "$LOG_LINES" > t.t.$$
  echo "$ERR_LINES" > t2.t.$$
  echo "$OK_LINES" > t3.t.$$
done }
LOG_LINES=`cat "t.t.$$"`
ERR_LINES=`cat "t2.t.$$"`
OK_LINES=`cat "t3.t.$$"`
rm t.t.$$
rm t2.t.$$
rm t3.t.$$

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

if [ -f "$FILTER_LIST" ] ; then
   TMP=`echo "$TMP" | fgrep -v -f "$FILTER_LIST"`
fi
# Save the new set of filters so we don't double-count
if [ -n "$TMP" ] ; then
   echo "$TMP" > "$FILTER_LIST"
elif [ -f "$FILTER_LIST" ] ; then
   rm "$FILTER_LIST"
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

/usr/local/bin/spar list_blocked.sp > blocked.out
COUNTRY_SUMMARY=`fgrep Country <blocked.out | cut -d: -f2 | sort | uniq -c | sort -rn | head -30`
TOTAL_ON_FILE=`fgrep Country <blocked.out | wc -l`

# Chart the trend.

bash graph_series.sh "threat_trend" $HTTP_EVENTS $SSH_EVENTS $MAIL_EVENTS $SPAM_EVENTS

# Dump the logins.

TOP_LOGINS=`/usr/local/bin/spar list_logins.sp | sort -nr -k2 | fgrep -v "logins:" | head -n 30`
echo "$TOP_LOGINS" > /var/www/html/pegasoft/ssds/top_logins.frag

# Summary:

echo "Errors: $ERR_LINES" > /var/www/html/pegasoft/ssds/daily_summary.frag
echo "OK:     $OK_LINES" >> /var/www/html/pegasoft/ssds/daily_summary.frag
echo "Total:  $LOG_LINES lines" >> /var/www/html/pegasoft/ssds/daily_summary.frag
echo >> /var/www/html/pegasoft/ssds/daily_summary.frag
echo "New HTTP Blocks:      $HTTP_EVENTS" >> /var/www/html/pegasoft/ssds/daily_summary.frag
echo "New SSH  Blocks:      $SSH_EVENTS" >> /var/www/html/pegasoft/ssds/daily_summary.frag
echo "New Mail Blocks:      $MAIL_EVENTS" >> /var/www/html/pegasoft/ssds/daily_summary.frag
echo "New Spam Blocks:      $SPAM_EVENTS" >> /var/www/html/pegasoft/ssds/daily_summary.frag
echo "Currently Blocked:    $CURRENT_BLOCKS" >> /var/www/html/pegasoft/ssds/daily_summary.frag
echo "Currently Monitoring: $TOTAL_ON_FILE" >> /var/www/html/pegasoft/ssds/daily_summary.frag

echo "$COUNTRY_SUMMARY" > /var/www/html/pegasoft/ssds/top_countries.frag

