separate;

configuration world is

------------------------------------------------------------------------------
-- This file contains global types and settings
------------------------------------------------------------------------------

pragma suppress( low_priority_todos_for_release );
-- For this version, allow some work to be incomplete

------------------------------------------------------------------------------
-- VERSION
------------------------------------------------------------------------------

version : constant string := "0.1";

------------------------------------------------------------------------------
-- Shell Imports
------------------------------------------------------------------------------

type shell_import_string is new string;

HOSTNAME : shell_import_string := "";
pragma unchecked_import( shell, HOSTNAME );
-- this is unchecked as hostname may not be defined if run from cron

------------------------------------------------------------------------------
-- STANDARD DATA TYPES
--
-- "raw" indicates unvalidated data.
------------------------------------------------------------------------------

-- type port_string is new string;
type dns_string is new string;
type comment_string is new string;
type date_string is new string;
type timestamp_string is new string;
type country_string is new string;
type file_path is new string;
type email_string is new string;

type grace_count is new natural;

------------------------------------------------------------------------------
-- Usernames
--
-- Standard UNIX limits usernames to 8 characters.  32 are allowed on Linux,
-- though some commands may be affected (like PS showing UID's instead for
-- long usernames).
------------------------------------------------------------------------------

type user_string is new string;
type raw_user_string is new string;

------------------------------------------------------------------------------
-- IP Numbers
------------------------------------------------------------------------------

type ip_string is new string;
type raw_ip_string is new ip_string;

------------------------------------------------------------------------------
-- Firewall Type
------------------------------------------------------------------------------

type firewall_kinds is (
  iptables_firewall,
  iptables_old_firewall,
  initd_iptables_firewall,
  firewalld_firewall,
  suse_firewall
);

-- firewall_kind is defind in config/config.inc.sp

------------------------------------------------------------------------------
-- Operating Mode
------------------------------------------------------------------------------

type operating_modes is (
  monitor_mode,
  honeypot_mode,
  local_blocking_mode,
  shared_blocking_mode
);

-- mode is defined in config.inc.sp

------------------------------------------------------------------------------
-- Alert Types
------------------------------------------------------------------------------

type alert_kinds is (
  error_limit_alert,
  space_limit_alert,
  blocks_limit_alert,
  http_limit_alert,
  mail_limit_alert,
  sshd_limit_alert,
  spam_limit_alert,
  outgoing_email_limit_alert
);

------------------------------------------------------------------------------
-- Alert Actions
------------------------------------------------------------------------------

type alert_action is (
  block_action,
  email_action,
  evade_action,
  shutdown_action
);

end world;

-- vim: ft=spar

