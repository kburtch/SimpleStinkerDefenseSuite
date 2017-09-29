#!/bin/bash

# Reset the firewall
# Sleep is to delay to avoid race conditions
nohup bash sshd_daemon.sh &
#sleep 1
nohup bash mail_daemon.sh &
#sleep 1
nohup bash http_daemon.sh &

