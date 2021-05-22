#!/usr/local/bin/spar

-- Reset the firewall

if files.exists( "lock/suspend.lck" ) then
   rm "lock/suspend.lck";
end if;

-- Reset any locks in the BDB database

f : btree_io.file( string );
btree_io.recover( f, "data/blocked_ip.btree" );

-- Start all the daemons

nohup bash sshd_daemon.sh & ;
nohup bash mail_daemon.sh & ;
nohup bash http_daemon.sh & ;

