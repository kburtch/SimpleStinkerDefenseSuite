#!/user/local/bin/spar

-- Reset the firewall

nohup bash sshd_daemon.sh &
nohup bash mail_daemon.sh &
nohup bash http_daemon.sh &

