separate;

-- The location of the sshd log file

sshd_violations_file_path : string := "/var/log/secure";

-- The location of the Apache web server log file

http_violations_file_path : string := "/var/log/httpd/pegasoft-access_log";

-- The operating mode
-- as defind in lib/world.inc.sp

mode : constant operating_modes := monitor_mode;

-- The kind of firewall
-- as defind in lib/world.inc.sp

firewall_kind : constant firewall_kinds := iptables_firewall;

-- vim: ft=spar

