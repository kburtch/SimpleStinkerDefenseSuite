#!/bin/bash

# Stop the firewall daemons

TMP=`ps -ef`
TMP=`echo "$TMP" | fgrep "wash_blocked.sp"`
if [ -n "$TMP" ] ; then
   echo "wash_blocked is still running"
   exit 192
fi

if [ -f "run/http_daemon.pid" ] ; then
   kill `cat run/http_daemon.pid`
fi
if [ -f "run/sshd_daemon.pid" ] ; then
   kill `cat run/sshd_daemon.pid`
fi
if [ -f "run/mail_daemon.pid" ] ; then
   kill `cat run/mail_daemon.pid`
fi

