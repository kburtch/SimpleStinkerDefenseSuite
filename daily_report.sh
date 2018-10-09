#!/bin/bash

REPORT_DATE=`date '+%b %e'`

LOG_LINES=`fgrep "$REPORT_DATE" log/blocker.log | wc -l`
ERR_LINES=`fgrep "$REPORT_DATE" log/blocker.log | fgrep ':ERROR:' | fgrep -v "Nickto" | wc -l`
OK_LINES=`fgrep "$REPORT_DATE" log/blocker.log | fgrep ':OK' | wc -l`

echo "Errors: $ERR_LINES"
echo "OK:     $OK_LINES"
echo "Total:  $LOG_LINES lines"
echo
echo "Errors"
echo
fgrep "$REPORT_DATE" log/blocker.log | fgrep ':ERROR:' | fgrep -v "Nikto"
echo
echo "Reports"
echo

TMP=`fgrep "$REPORT_DATE" log/blocker.log | fgrep ':OK' | fgrep Process`
HTTP_SUMMARY=`echo "$TMP" | fgrep "http_blocker"`
SSH_SUMMARY=`echo "$TMP" | fgrep "sshd_blocker"`
MAIL_SUMMARY=`echo "$TMP" | fgrep "mail_blocker"`

HTTP_EVENTS=`echo "$HTTP_SUMMARY" | cut -d\; -f2 | cut -d= -f2 | tr -d ' '`
SSH_NEW=`echo "$SSH_SUMMARY" | cut -d\; -f2 | cut -d= -f2 | tr -d ' '`
SSH_OLD=`echo "$SSH_SUMMARY" | cut -d\; -f4 | cut -d= -f2 | tr -d ' '`
let "SSH_EVENTS=SSH_NEW+SSH_OLD"
MAIL_EVENTS=`echo "$MAIL_SUMMARY" | cut -d\; -f2 | cut -d= -f2 | tr -d ' '`

CURRENT_BLOCKS=`ipset -L blocklist  | wc -l`
let "CURRENT_BLOCKS=CURRENT_BLOCKS-8"

/usr/local/bin/spar list_blocked.sp > blocked.out
COUNTRY_SUMMARY=`fgrep Country <blocked.out | cut -d: -f2 | sort | uniq -c | sort -rn | head -30`
TOTAL_ON_FILE=`fgrep Country <blocked.out | wc -l`

#bash graph_series.sh "threat_trend" $HTTP_EVENTS $SSH_EVENTS $MAIL_EVENTS

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
echo "Currently Blocked:    $CURRENT_BLOCKS" >> /var/www/html/pegasoft/ssds/daily_summary.frag
echo "Currently Monitoring: $TOTAL_ON_FILE" >> /var/www/html/pegasoft/ssds/daily_summary.frag

echo "$COUNTRY_SUMMARY" > /var/www/html/pegasoft/ssds/top_countries.frag

