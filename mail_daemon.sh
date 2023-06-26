#!/bin/bash
#
# Run the mail blocker like a daemon.
#
# This script writes the mail log to a named pipe, where it is
# read by the mail blocker.
# ----------------------------------------------------------------------------
shopt -s -o nounset

declare -r SCRIPT=${0##*/}
declare -r BLOCKER_ROOT="/root/ssds" # GET FROM CONFIG
declare -r MAIL_PIPE="$BLOCKER_ROOT""/run/mail_pipe"
declare -r MAIL_PID_FILE="$BLOCKER_ROOT""/run/mail_daemon.pid"
declare -r MAIL_TAIL_PID_FILE="$BLOCKER_ROOT""/run/mail_tail_pids"
declare -i TAIL_PID=0
declare -i BLOCKER_PID=0
declare -i STATUS=0
declare    OPT_VERBOSE=

#  CLEANUP
#
# Stop the background processes and erase the named pipe
# ----------------------------------------------------------------------------

function cleanup {
  if [ -n "$OPT_VERBOSE" ] ; then
     echo `date`": $SCRIPT: $LINENO: Stopping tail"
  fi

  ( while read TAIL_PID ; do
     if [ $TAIL_PID -ne 0 ] ; then
        /bin/ps -p "$TAIL_PID" > /dev/null
        if [ "$?" -eq 0 ] ; then
           kill "$TAIL_PID"
           if [ "$?" -eq 0 ] ; then
              if [ -n "$OPT_VERBOSE" ] ; then
                 echo "killed tail pid: $TAIL_PID"
              fi
           fi
        fi
     fi
  done ) < "$MAIL_TAIL_PID_FILE"

  # Killing the tail should send EOF to the pipe.  As a precaution,
  # wait and force mail blocker to stop if necessary.
  sleep 5

  if [ -n "$OPT_VERBOSE" ] ; then
     echo `date`": $SCRIPT: $LINENO: Stopping mail_blocker"
  fi

  if [ "$BLOCKER_PID" -ne 0 ] ; then
     /bin/ps -p "$BLOCKER_PID" > /dev/null
     if [ "$?" -eq 0 ] ; then
        kill "$BLOCKER_PID"
     fi
  fi

  # Remove the named pipe

  if [ -n "$OPT_VERBOSE" ] ; then
     echo `date`": $SCRIPT: $LINENO: Removing named pipe"
  fi
  rm "$MAIL_PIPE"
  rm "$MAIL_TAIL_PID_FILE"

  if [ -n "$OPT_VERBOSE" ] ; then
     echo `date`": $SCRIPT: $LINENO: Done"
  fi
  rm "$MAIL_PID_FILE"
}

function usage {
  echo "$SCRIPT [-v]"
  echo
  echo "Runs the mail blocker in real-time, blocking suspicious ip's"
  echo "kill the pid in $MAIL_PID_FILE to stop.  Run this as an ongoing"
  echo "background process."
}

# Usage
# ----------------------------------------------------------------------------

if [ $# -gt 0 ] ; then
   if [ "$1" = "-h" ] ; then
      usage
      exit 1
   elif [ "$1" = "--help" ] ; then
      usage
      exit 1
   elif [ "$1" = "-v" ] ; then
      OPT_VERBOSE="-v"
   fi
fi

# Sanity Tests
# ----------------------------------------------------------------------------

if [ "$LOGNAME" != "root" ] ; then
   echo "$SCRIPT: $LINENO: Must run script as root" >&2
   exit 192
fi
if [ ! -r "$BLOCKER_ROOT" ] ; then
   echo "$SCRIPT: $LINENO: BLOCKER_ROOT is not readable" >&2
   exit 192
fi
if [ ! -w "$BLOCKER_ROOT" ] ; then
   echo "$SCRIPT: $LINENO: BLOCKER_ROOT is not readable" >&2
   exit 192
fi
if [ ! -w "$BLOCKER_ROOT" ] ; then
   echo "$SCRIPT: $LINENO: BLOCKER_ROOT is not readable" >&2
fi
OLD_PID=`cat "$MAIL_PID_FILE" 2>> /dev/null`
if [ -n "$OLD_PID" ] ; then
   /bin/ps -p "$OLD_PID" > /dev/null
   if [ "$?" -ne 0 ] ; then
      echo "$SCRIPT: $LINENO: WARNING: overwriting stale MAIL_PID_FILE" >&2
      echo "$$" > "$MAIL_PID_FILE"
   else
      echo "$SCRIPT: $LINENO: ERROR: aborting - may already be running as PID $OLD_PID" >&2
      exit 192
   fi
else
   echo "$$" > "$MAIL_PID_FILE"
fi

# Start the mail blocker
# ----------------------------------------------------------------------------

# Create a named pipe

if [ -n "$OPT_VERBOSE" ] ; then
   echo `date`": $SCRIPT: $LINENO: Creating named pipe $MAIL_PIPE"
fi

if [ -w "$MAIL_PIPE" ] ; then
   rm "$MAIL_PIPE"
fi
mkfifo -m 600 "$MAIL_PIPE"

if [ -n "$OPT_VERBOSE" ] ; then
   echo `date`": $SCRIPT: $LINENO: Starting mail blocker"
fi

# Handle interrupts

trap 'cleanup;exit' SIGHUP SIGINT SIGTERM

# Start the MAIL blocker, reading from the pipe

nice spar -m mail_blocker.sp -D $OPT_VERBOSE -f "$MAIL_PIPE" &
#nice /home/ken/ada/SparForte/src/spar  -m mail_blocker.sp -D $OPT_VERBOSE -f "$MAIL_PIPE" &
if [ $? -ne 0 ] ; then
   echo `date`": $SCRIPT: $LINENO: ERROR: mail_blocker failed - status $?" >&2
   cleanup
   exit
fi
BLOCKER_PID=$!
if [ -n "$OPT_VERBOSE" ] ; then
   echo `date`": $SCRIPT: $LINENO: mail_blocker pid: $BLOCKER_PID"
fi

# Start a tail command, writing the mail log to the pipe
# Continue reading even if the log file is rotated.

if [ -n "$OPT_VERBOSE" ] ; then
   echo `date`": $SCRIPT: $LINENO: Starting tail"
fi

FILES=`cd utils; spar export_mail_file_paths`
if [ "$FILES" = "" ] ; then
   echo `date`": $SCRIPT: $LINENO: no files configured" >&2
   exit 192
fi

echo "$FILES" | while read FILE ; do
   if [ ! -f "$FILE" ] ; then
      echo `date`": $SCRIPT: $LINENO: $FILE does not exist" >&2
      exit 192
   elif [ ! -r "$FILE" ] ; then
      echo `date`": $SCRIPT: $LINENO: $FILE is not readable" >&2
      exit 192
   fi
   nice tail --follow=name --retry --lines=0 "$FILE" > "$MAIL_PIPE" &
   STATUS=$?
   TAIL_PID=$!
   if [ $STATUS -ne 0 ] ; then
      echo `date`": $SCRIPT: $LINENO: tail failed - status $STATUS" >&2
      cleanup
      exit
   fi
   if [ -n "$OPT_VERBOSE" ] ; then
      echo `date`": $SCRIPT: $LINENO: tail pid: $TAIL_PID"
   fi
   echo "$TAIL_PID" >> "$MAIL_TAIL_PID_FILE"
done

# Wait until finished (if ever)

if [ -n "$OPT_VERBOSE" ] ; then
   echo `date`": $SCRIPT: $LINENO: Waiting on running subprocesses"
fi
wait
cleanup

