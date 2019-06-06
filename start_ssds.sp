#!/usr/local/bin/spar

-- Reset the firewall

if files.exists( "lock/suspend.lck" ) then
   rm "lock/suspend.lck";
end if;

nohup bash sshd_daemon.sh & ;
nohup bash mail_daemon.sh & ;
nohup bash http_daemon.sh & ;

