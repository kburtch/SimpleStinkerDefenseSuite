separate;

-- TODO: disabling blockers

-- The location of the sshd log file (default)

sshd_violations_file_path : file_path := "/var/log/secure";

-- The location of the Postfix log file (default)

smtp_violations_file_path : file_path := "/var/log/maillog";

-- The location of the Apache web server log files (default)
-- The default is the first path in the list.

http_violations_file_paths : array( 1..3 ) of file_path := (
  "/var/log/httpd/pegasoft-access_log",
  "/var/log/httpd/sparforte-access_log",
  "/var/log/httpd/willow-access_log"
);

-- The operating mode
-- as defind in lib/world.inc.sp

mode : constant operating_modes := monitor_mode;

-- The kind of firewall
-- as defind in lib/world.inc.sp

firewall_kind : constant firewall_kinds := iptables_firewall;

-- How many violations before blocking takes effect.

default_grace : constant grace_count := 1;

-- vim: ft=spar

