#!/usr/local/bin/spar

-- Stop the firewall daemons

TMP : string;

loop
   TMP := `ps -ef`;

   -- Do not stop if washed_blocked is running

   exit when strings.index( TMP, "wash_blocked.sp" ) = 0;
   ? "wash_blocked is running.  Wait until it is finished";
   delay 60.0;
   --   command_line.set_exit_status(192);
end loop;

-- Stop each of the log readers

if files.exists( "run/http_daemon.pid" ) then
   TMP := `cat "run/http_daemon.pid"`;
   kill "$TMP";
end if;

if files.exists( "run/sshd_daemon.pid" ) then
   TMP := `cat "run/sshd_daemon.pid"`;
   kill "$TMP";
end if;

if files.exists( "run/mail_daemon.pid" ) then
   TMP := `cat "run/mail_daemon.pid"`;
   kill "$TMP";
end if;

touch "lock/suspend.lck";

-- vim: set ft=spar
