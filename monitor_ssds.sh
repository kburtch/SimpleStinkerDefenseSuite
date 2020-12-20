#!/bin/bash
#
# A simple script to show a running report from the blocker log
#
# Ken Burtch
# ---------------------------------------------------------------------------

BLOCKER_LOG="log/blocker.log"

OPT_VERBOSE=
if [ "$1" = "-v" ] ; then
   OPT_VERBOSE=1
fi
if [ "$1" = "-h" ] ; then
   echo "usage: monitor_log.sh [-v]"
   exit 192
fi
if [ ! -r "$BLOCKER_LOG" ] ; then
   echo "unable to read blocker log '$BLOCKER_LOG'"
   exit 192
fi

START_TIME=`date +%s`

tput clear
echo

# Timeout does not work

tail -f log/blocker.log | ( while read LINE; do

# Default values

OK=${OK=0}
INFO=${INFO=0}
WARNING=${WARNING=0}
ERROR=${ERROR=0}
BLOCKED=${BLOCKED=0}
UNBLOCKED=${UNBLOCKED=0}
WASHES=${WASHES=0}
SSHD_THREAT=${SSHD_THREAT=0}
HTTP_THREAT=${HTTP_THREAT=0}
SMTP_THREAT=${SMTP_THREAT=0}
SPAM_THREAT=${SPAM_THREAT=0}

# Check Log

COLOR=""
TMP=`echo "$LINE" | fgrep OK`
if [ -n "$TMP" ] ; then
   COLOR=`tput setaf 2`
   TMP=`echo "$LINE" | fgrep blocked | fgrep -v Still`
   if [ -n "$TMP" ] ; then
      let "BLOCKED=$BLOCKED+1"
   fi
   TMP=`echo "$LINE" | fgrep unblocked`
   if [ -n "$TMP" ] ; then
      let "UNBLOCKED=$UNBLOCKED+1"
   fi
   let "OK=$OK+1"
fi
TMP=`echo "$LINE" | fgrep WARNING`
if [ -n "$TMP" ] ; then
   COLOR=`tput setaf 5`
   let "WARNING=$WARNING+1"
fi
TMP=`echo "$LINE" | fgrep ERROR`
if [ -n "$TMP" ] ; then
   COLOR=`tput setaf 1`
   let "ERROR=$ERROR+1"
fi

# INFO

if [ -z "$COLOR" ] ; then
   COLOR=`tput setaf 7`
   let "INFO=$INFO+1"
   TMP=`echo "$LINE" | fgrep "End wash_blocked"`
   if [ -n "$TMP" ] ; then
      let "WASHES=$WASHES+1"
   fi
   TMP=`echo "$LINE" | fgrep "SSHD threat"`
   if [ -n "$TMP" ] ; then
      let "SSHD_THREAT=$SSHD_THREAT+1"
   fi
   TMP=`echo "$LINE" | fgrep "HTTP threat"`
   if [ -n "$TMP" ] ; then
      let "HTTP_THREAT=$HTTP_THREAT+1"
   fi
   TMP=`echo "$LINE" | fgrep "SMTP threat"`
   if [ -n "$TMP" ] ; then
      let "SMTP_THREAT=$SMTP_THREAT+1"
   fi
   TMP=`echo "$LINE" | fgrep "SPAM threat"`
   if [ -n "$TMP" ] ; then
      let "SPAM_THREAT=$SPAM_THREAT+1"
   fi
   if [ -z "$OPT_VERBOSE" ] ; then
      LINE=""
   fi
fi

# Display Log Line

if [ -n "$LINE" ] ; then
   echo "$COLOR""$LINE"
   tput setaf 7
fi

# Elapsed Time

END_TIME=`date +%s`
let "ELAPSED=$END_TIME-$START_TIME"
let "HOUR_ELAPSED=$ELAPSED/3600"
let "MIN_ELAPSED=$ELAPSED-$HOUR_ELAPSED*3600"
let "MIN_ELAPSED=$MIN_ELAPSED/60"
let "SEC_ELAPSED=$ELAPSED-$MIN_ELAPSED*60-$HOUR_ELAPSED*3600"
if [ "${#MIN_ELAPSED}" = 1 ] ; then
   MIN_ELAPSED="0""$MIN_ELAPSED"
fi
if [ "${#SEC_ELAPSED}" = 1 ] ; then
   SEC_ELAPSED="0""$SEC_ELAPSED"
fi

# Display Info Bar

tput sc
tput cup 0 0
tput smso
echo -n "$HOSTNAME - SSHD:$SSHD_THREAT HTTP:$HTTP_THREAT MAIL:$SMTP_THREAT SPAM:$SPAM_THREAT OK:$OK INFO:$INFO WARN:$WARNING ERR:$ERROR BLK:$BLOCKED UNBLK:$UNBLOCKED WASH:$WASHES - $HOUR_ELAPSED"":""$MIN_ELAPSED"":""$SEC_ELAPSED"
tput el
tput rmso
tput rc

done )

