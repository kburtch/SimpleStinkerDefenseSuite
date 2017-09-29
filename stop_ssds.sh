#!/bin/bash

# Stop the firewall daemons

kill `cat run/http_daemon.pid`
kill `cat run/sshd_daemon.pid`
kill `cat run/mail_daemon.pid`

