separate;

configuration ssds_config is

-- Constant Specifications

dashboard_path : constant file_path;
project_path : constant file_path;
operating_mode : constant operating_modes;
firewall_kind : constant firewall_kinds;
default_grace : constant grace_count;
mail_grace    : constant grace_count;
alert_email   : constant email_string;
report_email  : constant email_string;
ssh_ping_user : constant string;
ssh_port : constant string;

-- TODO: disabling individual blockers

-- The dashboard location

dashboard_path : constant file_path := "/var/www/html/pegasoft/ssds";

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

http_violations_file_paths : array( 1..2 ) of file_path := (
  "/var/log/httpd/pegasoft-access_log",
  "/var/log/httpd/sparforte-access_log"
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
-- A blank report email will not send a daily report.

alert_email   : constant email_string := "ken@pegasoft.ca";
report_email  : constant email_string := "";

-- The ssh account to test SSH

ssh_ping_user : constant string := "ken@localhost";
ssh_port : constant string := "22";

-- List of whitelisted IP numbers
-- IP number and description in CSV format pairs

ip_whitelist_config : constant array(1..5) of string :=
( "127.0.0.1,localhost",
  "45.56.68.190,lntxap01",
  "198.58.125.175,armitage",
  "199.102.130.97,nwic",
  "97.107.227.199,lawyer" );

-- Number of events to trigger an alert (by type)

alert_thresholds : constant array(error_limit_alert..spam_limit_alert) of integer :=
(
  50,  -- error event maximum limit
  250, -- space event maximum limit (megabytes)
  50000, -- ip blocks maximum limit
  150, -- http event maximum limit
  150, -- mail event maximum limit
  150, -- sshd event maximum limit
  300  -- spam event maximum limit
);

-- The action to take

alert_actions : constant array(error_limit_alert..spam_limit_alert) of alert_action :=
(
  email_action, -- error alert action
  email_action, -- space alert action
  email_action, -- ip blocks alert action
  email_action, -- http alert action
  email_action, -- mail alert action
  email_action, -- sshd alert action
  email_action  -- spam alert action
);

end ssds_config;

-- vim: ft=spar

