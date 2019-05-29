separate;

configuration config is

-- TODO: disabling individual blockers

-- The location of the project root directory.

project_path : constant file_path := "/root/ssds";

-- The location of the sshd log file (default)
-- This is the log containing remote login violations.

sshd_violations_file_path : file_path := "/var/log/secure";

-- The location of the Postfix/Amavis log file (default)
-- This is the log containing mail violations.

smtp_violations_file_path : file_path := "/var/log/maillog";

-- The locations of the Apache web server access log files
-- to check for violations.  Typically, this entry is one per
-- website on this server.
-- The default is the first path in the list.

http_violations_file_paths : array( 1..3 ) of file_path := (
  "/var/log/httpd/pegasoft-access_log",
  "/var/log/httpd/sparforte-access_log",
  "/var/log/httpd/willow-access_log"
);

-- The mode the blocker is operating in.  For example, is the
-- blocker monitoring/testing or actively blocking.
-- The enumerated values are defined in lib/world.inc.sp

operating_mode : constant operating_modes := local_blocking_mode;

-- The kind of firewall on this server.
-- The enumerated values are defined in lib/world.inc.sp

firewall_kind : constant firewall_kinds := iptables_firewall;

-- How many violations to forgive before blocking takes effect.
-- The value must be greater than zero.  The default is 1.
-- Setting the grace to zero doesn't necessarily provide better
-- defense, as an attacker usually tries more than once per
-- session.
-- Optionally, provide a different grace amount for SMTP/Spam
-- violations.

default_grace : constant grace_count := 1;
mail_grace    : constant grace_count := 4;

-- The email address to receive alerts.

alert_email   : constant email_string := "ken@pegasoft.ca";
report_email  : constant email_string := "ken@pegasoft.ca";

-- The ssh account to test SSH

ssh_ping_user : constant string := "ken@localhost";
ssh_port : constant string := "22";

-- List of whitelisted IP numbers
-- IP number and description in CSV format pairs

ip_whitelist_config : constant array(1..6) of string :=
( "127.0.0.1,localhost",
  "45.56.68.190,lntxap01",
  "198.58.125.175,armitage",
  "209.159.182.101,home",
  "157.52.4.6,ludbrook",
  "207.219.237.66,tier1" );

end config;

-- vim: ft=spar

