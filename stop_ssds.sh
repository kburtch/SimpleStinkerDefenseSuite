#!/bin/bash

# Stop the firewall daemons

if [ -f "run/http_daemon.pid" ] ; then
   kill `cat run/http_daemon.pid`
fi
if [ -f "run/sshd_daemon.pid" ] ; then
   kill `cat run/sshd_daemon.pid`
fi
if [ -f "run/mail_daemon.pid" ] ; then
   kill `cat run/mail_daemon.pid`
fi

