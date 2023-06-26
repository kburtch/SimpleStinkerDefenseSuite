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

type raw_user_string is new string;
type user_string is new string
affirm
  if not strings.is_graphic( user_string ) then
     user_string := "";
  end if;
  -- Spaces are considered graphic...but aren't allowed in a username
  if strings.index( user_string, " " ) > 0 then
     user_string := "";
  end if;
  -- Implementation dependent.  Linux allows up to 32 characters.
  if strings.length( user_string ) > 32 then
     user_string := "";
  end if;
  -- as a precaution, strip dollar signs
  if strings.index( user_string, "$" ) > 0 then
     user_string := strings.replace_all( user_string, "$", "_" );
  end if;
end affirm;


------------------------------------------------------------------------------
-- IP Numbers
------------------------------------------------------------------------------

type raw_ip_string is new string;

function validate_ip( ip : raw_ip_string ) return raw_ip_string is
  p : positive := 1;

  procedure expect_byte( result : out boolean ) is
    byte : string;
    ch   : character;
  begin
    loop
      exit when p > strings.length( ip );
      ch := strings.element( string( ip ), p );
      exit when not strings.is_digit( ch );
      byte := @ & ch;
      p := @ + 1;
    end loop;
    if byte /= "" then
       if numerics.value( byte ) > 255 then
          byte := "";
       end if;
    end if;
    result := byte /= "";
  end expect_byte;

  procedure expect_period( result : out boolean ) is
    period : boolean;
  begin
    declare
      this_p : constant integer copies p;
    begin
      if this_p > strings.length( ip ) then
         result := false;
         return;
      end if;
    end;
    period := strings.element( string( ip ), p ) = '.';
    p := @ + 1;
    result := period;
  end expect_period;

  result : boolean;
begin
 if ip = "" then
     return "";
  end if;
  expect_byte( result );
  if not result then
     return "";
  end if;
  expect_period( result );
  if not result then
     return "";
  end if;
  expect_byte( result );
  if not result then
     return "";
  end if;
  expect_period( result );
  if not result then
     return "";
  end if;
  expect_byte( result );
  if not result then
     return "";
  end if;
  expect_period( result );
  if not result then
     return "";
  end if;
  expect_byte( result );
  if not result then
     return "";
  end if;
  if p <= strings.length( ip ) then
     return "";
  end if;
  return ip;
end validate_ip;

type ip_string is new string
affirm
  if ip_string /= "" then
     if validate_ip( raw_ip_string( ip_string ) ) = "" then
        ip_string := "";
     end if;
  end if;
end affirm;

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

