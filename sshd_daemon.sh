#!/bin/bash
#
# Run the sshd blocker like a daemon.
#
# This script writes the sshd log to a named pipe, where it is
# read by the sshd blocker.
# ----------------------------------------------------------------------------
shopt -s -o nounset

declare -r SCRIPT=${0##*/}
declare -r BLOCKER_ROOT="/root/secure"
declare -r SSHD_PIPE="$BLOCKER_ROOT""/run/sshd_pipe"
declare -r SSHD_PID_FILE="$BLOCKER_ROOT""/run/sshd_daemon.pid"
declare -i TAIL_PID=0
declare -i BLOCKER_PID=0
declare    OPT_VERBOSE=

#  CLEANUP
#
# Stop the background processes and erase the named pipe
# ----------------------------------------------------------------------------

function cleanup {
  echo `date`": $SCRIPT: $LINENO: Stopping tail"

  if [ "$TAIL_PID" -ne 0 ] ; then
     /bin/ps -p "$TAIL_PID" > /dev/null
     if [ "$?" -eq 0 ] ; then
        kill "$TAIL_PID"
     fi
  fi

  # Killing the tail should send EOF to the pipe.  As a precaution,
  # wait and force sshd blocker to stop if necessary.
  sleep 5

  echo `date`": $SCRIPT: $LINENO: Stopping sshd_blocker"

  if [ "$BLOCKER_PID" -ne 0 ] ; then
     /bin/ps -p "$BLOCKER_PID" > /dev/null
     if [ "$?" -eq 0 ] ; then
        kill "$BLOCKER_PID"
     fi
  fi

  # Remove the named pipe

  echo `date`": $SCRIPT: $LINENO: Removing named pipe"

  rm "$SSHD_PIPE"
  echo `date`": $SCRIPT: $LINENO: Done"
  rm "$SSHD_PID_FILE"
}

function usage {
  echo "$SCRIPT [-v]"
  echo
  echo "Runs the sshd blocker in real-time, blocking suspicious ip's"
  echo "kill the pid in $SSHD_PID_FILE to stop.  Run this as an ongoing"
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
OLD_PID=`cat "$SSHD_PID_FILE" 2>> /dev/null`
if [ -n "$OLD_PID" ] ; then
   /bin/ps -p "$OLD_PID" > /dev/null
   if [ "$?" -ne 0 ] ; then
      echo "$SCRIPT: $LINENO: WARNING: overwriting stale SSHD_PID_FILE" >&2
      echo "$$" > "$SSHD_PID_FILE"
   else
      echo "$SCRIPT: $LINENO: ERROR: aborting - may already be running as PID $OLD_PID" >&2
      exit 192
   fi
else
   echo "$$" > "$SSHD_PID_FILE"
fi

# Start the sshd blocker
# ----------------------------------------------------------------------------

# Create a named pipe

echo `date`": $SCRIPT: $LINENO: Creating named pipe $SSHD_PIPE"

if [ -w "$SSHD_PIPE" ] ; then
   rm "$SSHD_PIPE"
fi
mkfifo -m 600 "$SSHD_PIPE"

echo `date`": $SCRIPT: $LINENO: Starting sshd blocker"

# Handle interrupts

trap 'cleanup;exit' SIGHUP SIGINT SIGTERM

# Start the SSHD blocker, reading from the pipe

nice spar sshd_blocker.sp -D $OPT_VERBOSE -f "$SSHD_PIPE" &
if [ $? -ne 0 ] ; then
   echo `date`": $SCRIPT: $LINENO: ERROR: sshd_blocker failed - status $?" >&2
   cleanup
   exit
fi
BLOCKER_PID=$!
echo `date`": $SCRIPT: $LINENO: sshd_blocker pid: $BLOCKER_PID"

# Start a tail command, writing the sshd log to the pipe
# Continue reading even if the log file is rotated.

echo `date`": $SCRIPT: $LINENO: Starting tail"

nice tail --follow=name --retry "/var/log/secure" > "$SSHD_PIPE" &
if [ $? -ne 0 ] ; then
   echo `date`": $SCRIPT: $LINENO: tail failed - status $?" >&2
   cleanup
   exit
fi
TAIL_PID=$!
echo `date`": $SCRIPT: $LINENO: tail pid: $TAIL_PID"

# Wait until finished (if ever)

echo `date`": $SCRIPT: $LINENO: Waiting while running"
wait
cleanup
