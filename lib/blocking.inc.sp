separate;

------------------------------------------------------------------------------
-- This file contains firewall blocking routines.
------------------------------------------------------------------------------

-- Mandatory commands

IPSET_CMD     : limited command := "/sbin/ipset";
IPTABLES_CMD  : limited command := "/sbin/iptables";
IP6TABLES_CMD : limited command := "/sbin/ip6tables";

-- This does not exist on Ubuntu

banned_threshhold : constant natural := 3;

type blocking_status is (
  unblocked_blocked,
  probation_blocked,
  short_blocked,
  banned_blocked,
  blacklisted_blocked
);

type an_offender is record
     source_ip       : ip_string;
     source_name     : dns_string;
     source_country  : country_string;
     location        : string;
     sshd_blocked    : blocking_status;
     sshd_blocked_on : timestamp_string;
     sshd_offences   : natural;
     mail_blocked    : blocking_status;
     mail_blocked_on : timestamp_string;
     mail_offences   : natural;
     spam_blocked    : blocking_status;
     spam_blocked_on : timestamp_string;
     spam_offences   : natural;
     http_blocked    : blocking_status;
     http_blocked_on : timestamp_string;
     http_offences   : natural;
     grace           : grace_count;
     created_on      : timestamp_string;
     logged_on       : timestamp_string;
     updated_on      : timestamp_string;
     sourced_from    : string;
     data_type       : data_types;
end record;

offender_path : constant file_path := "data/blocked_ip.btree";
offender_buffer_width : constant positive := 2048;

offender_file : btree_io.file( an_offender );

-----------------------------------------------------------------------------
-- Exported Subprograms
-----------------------------------------------------------------------------

procedure block( offender : ip_string );
pragma assumption( used, block );

procedure unblock( offender : ip_string );
pragma assumption( used, unblock );

function clear_firewall_to_baseline return boolean;
pragma assumption( used, clear_firewall_to_baseline );

procedure reset_firewall_to_defaults;
pragma assumption( used, reset_firewall_to_defaults );

procedure sshd_record_and_block( source_ip : ip_string; logged_on : timestamp_string; ts : timestamp_string; is_daemon : boolean; reason : string; kind : login_kind );
pragma assumption( used, sshd_record_and_block );

procedure mail_record_and_block( source_ip : ip_string; logged_on : timestamp_string; ts : timestamp_string; is_daemon : boolean; reason : string );
pragma assumption( used, mail_record_and_block );

procedure spam_record_and_block( source_ip : ip_string; logged_on : timestamp_string; ts : timestamp_string; is_daemon : boolean; reason : string );
pragma assumption( used, spam_record_and_block );

procedure http_record_and_block( source_ip : ip_string; logged_on : timestamp_string; ts : timestamp_string; is_daemon : boolean; reason : string );
pragma assumption( used, http_record_and_block );

procedure foreign_record_and_block( source_ip : ip_string; logged_on : timestamp_string; ts : timestamp_string; reason : string );
pragma assumption( used, foreign_record_and_block );

function number_blocked return natural;
pragma assumption( used, number_blocked );

function reblock_all return natural;
pragma assumption( used, reblock_all );

procedure startup_blocking;
pragma assumption( used, startup_blocking );

procedure shutdown_blocking;
pragma assumption( used, shutdown_blocking );


-----------------------------------------------------------------------------
-- Firewall Functions
-----------------------------------------------------------------------------


-- BLOCK
--
-- Block an offending IP number using the configured firewall.
-----------------------------------------------------------------------------

procedure block( offender : ip_string ) is
  -- old_log_level : a_log_level := log_level_start;
  old_log_level : logs.log_level;
begin
  logs.level_begin( old_log_level );
  if operating_mode = monitor_mode then
     logs.info( offender & " would have been blocked" );
  else
     case firewall_kind is
     when iptables_firewall =>
       IPSET_CMD( "-q", "test", "blocklist", offender );
       if $? /= 0 then
          IPSET_CMD( "add", "blocklist", offender );
       end if;
     when iptables_old_firewall =>
       IPTABLES_CMD( "-I", "INPUT",  "1", "-s", offender, "-j", "DROP" );
       IPTABLES_CMD( "-I", "OUTPUT", "1", "-d", offender, "-j", "REJECT" );
     when firewalld_firewall =>
       "/bin/firewall-cmd"( "--zone=public", "--add-rich-rule=" & ASCII.Quotation & "rule family='ipv4' source address='$offender'" & ASCII.Quotation & " drop" );
     when suse_firewall =>
        put_line( standard_error, "error - not implemented yet" );
     when others =>
        put_line( standard_error, "error - unexpected firewall type" );
     end case;

     if os.status = 0 then
        logs.ok( offender & " was blocked" );
     else
        put_line( standard_error, "error " & strings.image( os.status ) & " on blocking " & offender );
     end if;
  end if;
  logs.level_end( old_log_level );
  -- Record the blocked ip
end block;


-- UNBLOCK
--
-- Permit a blocked offender access to the server.
-----------------------------------------------------------------------------

procedure unblock( offender : ip_string ) is
  -- old_log_level : a_log_level := log_level_start;
  old_log_level : logs.log_level;
begin
  logs.level_begin( old_log_level );
  if operating_mode = monitor_mode then
     logs.info( offender & " would have been unblocked" );
  else
     case firewall_kind is
     when iptables_firewall =>
       IPSET_CMD( "-q", "test", "blocklist", offender );
       if $? = 0 then
          IPSET_CMD( "del", "blocklist", offender );
          if os.status = 0 then
             logs.ok( offender & " was unblocked" );
          else
             logs.error( "error" & strings.image( os.status ) & " on unblocking " & offender );
     end if;
       end if;
     when iptables_old_firewall =>
       null;
     when firewalld_firewall =>
       null;
     when suse_firewall =>
       null;
     when others =>
        put_line( standard_error, "error - unexpected firewall type" );
     end case;

  end if;
  logs.level_end( old_log_level );
end unblock;


-- CLEAR FIREWALL
--
-----------------------------------------------------------------------------

function clear_firewall_to_baseline return boolean is

  procedure reset_iptables is
    -- Return the firewall to its default state
    -- TODO: should this default to closed for all port and how to implement?
  begin
    -- This is a permissive firewall
    --IPTABLES_CMD( "-F" );                     -- clear rules
    --IPTABLES_CMD( "-X" );                     -- delete chains
    --IPTABLES_CMD( "-t", "nat", "-F" );
    --IPTABLES_CMD( "-t", "nat", "-X" );
    --IPTABLES_CMD( "-t", "mangle", "-F" );
    --IPTABLES_CMD( "-t", "mangle", "-X" );
    --IPTABLES_CMD( "-P", "INPUT", "ACCEPT" );
    --IPTABLES_CMD( "-P", "FORWARD", "ACCEPT" );
    --IPTABLES_CMD( "-P", "OUTPUT", "ACCEPT" );

    -- This is a restrictive firewall.  SSH only.
    -- https://wiki.centos.org/HowTos/Network/IPTables
    -- iptables -L -v to view
    -- TODO: This could likely be made fancier...
    -- logging should be enabled, for example.
       --  iptables -A INPUT -j LOG

    -- Temporarily set the input policy to accept to avoid getting locked out
    IPTABLES_CMD( "-P", "INPUT", "ACCEPT" );

    -- Flush (clear) all rules
    IPTABLES_CMD( "-F" );

    -- Accept connections on localhost
    IPTABLES_CMD( "-A", "INPUT", "-i", "lo", "-j", "ACCEPT" );

    -- Accept established, related connections
    IPTABLES_CMD( "-A", "INPUT", "-m", "state", "--state",
      "ESTABLISHED,RELATED", "-j", "ACCEPT" );

    -- Accept ICMP (Ping)
    IPTABLES_CMD( "-A", "INPUT", "-p", "icmp", "-j", "ACCEPT" );

    -- Accept SSH connections
    -- TODO: this rule must be dropped later or all SSH connections are
    -- accepted.
    --IPTABLES_CMD( "-A", "INPUT", "-p", "tcp", "--dport", "22", "-j",
    --  "ACCEPT" );

    -- Default policies
    IPTABLES_CMD( "-P", "INPUT", "DROP" );
    IPTABLES_CMD( "-P", "FORWARD", "DROP" );
    IPTABLES_CMD( "-P", "OUTPUT", "ACCEPT" );

    -- IPv6 Is needed for Postfix Red Hat 7
    -- Allow loopback and ICMP
    -- https://www.linode.com/docs/security/firewalls/control-network-traffic-with-iptables
    IP6TABLES_CMD( "-A", "INPUT", "-i", "lo", "-j", "ACCEPT" );
    IP6TABLES_CMD( "-A", "INPUT", "!", "-i", "lo", "-s", "::1/128", "-j", "REJECT" );
    IP6TABLES_CMD( "-A", "INPUT", "-p", "icmpv6", "-j", "ACCEPT" );
    IP6TABLES_CMD( "-A", "INPUT", "-j", "DROP" );
    IP6TABLES_CMD( "-A", "FORWARD", "-j", "DROP" );

    logs.info( "iptables reset " );
  end reset_iptables;

  total_clear : boolean := false;

begin
  if operating_mode /= monitor_mode and operating_mode /= honeypot_mode then
     case firewall_kind is
     when iptables_firewall =>

     -- Clear all blocked IP numbers
     --
     -- If it is not initialized, create the ipset blocklist set and rules
     -- to enforce.
     --
     -- To delete the whole set, use ipset destroy
     -- (Delete the iptables rules first)

        -- TODO: redirect output
        -- TODO: we should distinguish between soft and hard clears instead of
        -- using total clears.

        IPSET_CMD( "-q", "list", "blocklist" ) ;
        --ipset -q list blocklist >/dev/null 2>/dev/null ;
        if $? /= 0 then
           reset_iptables;
           IPSET_CMD( "create", "blocklist", "iphash" );
           IPTABLES_CMD( "-A", "INPUT", "-m", "set", "--match-set", "blocklist", "src",
             "-j", "DROP" ) ;
           IPTABLES_CMD( "-A", "INPUT", "-m", "set", "--match-set", "blocklist",  "dst",
             "-j", "REJECT" ) ;
           total_clear := true;
        else
           IPSET_CMD( "flush", "-q", "list", "blocklist" );
        end if;
     when iptables_old_firewall =>
       clear_iptables;
       -- TODO: add black listed ip's
     when initd_iptables_firewall =>
       /etc/init.d/iptables restart ;
     when suse_firewall =>
       /sbin/SuSEfirewall2 start ;
     when firewalld_firewall =>
       null; -- not yet implemented
     when others =>
       null; -- not yet implemented
     end case;
  end if;
  --TODO: process_blacklist;
  logs.info( "firewall cleared" );
  return total_clear;
end clear_firewall_to_baseline;


-- RESET FIREWALL
--
-- Clear the firewall rules and restore the current state.
-----------------------------------------------------------------------------

procedure reset_firewall_to_defaults is
  needs_rules : boolean;
begin
  needs_rules := clear_firewall_to_baseline;

  -- Block services
  if needs_rules then
     case firewall_kind is
     when iptables_firewall | iptables_old_firewall =>
        -- TODO: These are hard-coded for testing.  No logging active.
        -- Memcached must be protected.
        IPTABLES_CMD( "-A", "INPUT", "-p", "tcp", "--destination-port", "22", "-j", "ACCEPT" );
        IPTABLES_CMD( "-A", "INPUT", "-p", "tcp", "--destination-port", "25", "-j", "ACCEPT" );
        IPTABLES_CMD( "-A", "INPUT", "-p", "tcp", "--destination-port", "80", "-j", "ACCEPT" );
        IPTABLES_CMD( "-A", "INPUT", "-p", "tcp", "--destination-port", "110", "-j", "ACCEPT" );
        IPTABLES_CMD( "-A", "INPUT", "-p", "tcp", "--destination-port", "143", "-j", "ACCEPT" );
        IPTABLES_CMD( "-A", "INPUT", "-p", "tcp", "--destination-port", "443", "-j", "ACCEPT" );
        IPTABLES_CMD( "-A", "INPUT", "-p", "tcp", "--destination-port", "465", "-j", "ACCEPT" );
        IPTABLES_CMD( "-A", "INPUT", "-p", "tcp", "--destination-port", "587", "-j", "ACCEPT" );
        IPTABLES_CMD( "-A", "INPUT", "-p", "tcp", "--destination-port", "993", "-j", "ACCEPT" );
        IPTABLES_CMD( "-A", "INPUT", "-p", "tcp", "--destination-port", "995", "-j", "ACCEPT" );
        IPTABLES_CMD( "-A", "INPUT", "-p", "tcp", "--destination-port", ssh_port, "-j", "ACCEPT" );
        IPTABLES_CMD( "-A", "INPUT", "-p", "tcp", "--destination-port", "8080", "-j", "ACCEPT" );

        --IPTABLES_CMD( "-A", "INPUT", "-p", "tcp", "--destination-port", "11212", "-j", "REJECT" );
        --IPTABLES_CMD( "-A", "INPUT", "-p", "tcp", "--destination-port", "11211", "-j", "REJECT" );
        --IPTABLES_CMD( "-A", "INPUT", "-p", "tcp", "--destination-port", "11212", "-j", "REJECT" );
     when others =>
        put_line( standard_error, "not implemented yet" );
     end case;
  end if;

  -- TODO: restore the current state of blocked offenders

end reset_firewall_to_defaults;


-----------------------------------------------------------------------------
-- Blocking Functions
-----------------------------------------------------------------------------


-- SSH RECORD AND BLOCK
--
-- Record the offending IP number and block it with the configured firewall.
-- If it already has a record, update the existing record.
-----------------------------------------------------------------------------

procedure sshd_record_and_block( source_ip : ip_string; logged_on : timestamp_string; ts : timestamp_string; is_daemon : boolean; reason : string; kind : login_kind ) is
  ab : an_offender;
  msg : string;
  blocked_on : timestamp_string;
  freq : natural;
  old_log_level : logs.log_level;
begin
  logs.level_begin( old_log_level );
  if not btree_io.has_element( offender_file, string( source_ip ) ) then
     if reason /= "" then
        logs.info( source_ip ) @ ( reason );
     end if;
     -- TODO: refactor out initialization
     ab.source_ip       := source_ip;
     ab.source_name     := "";
     ab.source_country  := "";
     ab.location        := "";
     ab.sshd_blocked    := unblocked_blocked;
     ab.sshd_blocked_on := ts;
     ab.sshd_offences   := 0;
     ab.mail_blocked    := unblocked_blocked;
     ab.mail_blocked_on := ts;
     ab.mail_offences   := 0;
     ab.spam_blocked    := unblocked_blocked;
     ab.spam_blocked_on := ts;
     ab.spam_offences   := 0;
     ab.http_blocked    := unblocked_blocked;
     ab.http_blocked_on := ts;
     ab.http_offences   := 0;
     ab.grace           := default_grace+1;
     ab.created_on      := ts;
     ab.updated_on      := ts;
     ab.data_type       := real_data;
     -- The logged date may be invalid.  Use the current time if it is.
     if strings.is_digit( logged_on ) then
        ab.logged_on := logged_on;
     else
        ab.logged_on := ts;
     end if;

     -- calling card logins are automatically blocked
     if kind = calling_card then
        ab.grace := 0;
        logs.info( source_ip & " tried a calling card login" );
     -- privileged logins, if they exist, should not be publically accessible
     -- are automatically blocked
     elsif kind = privileged_login then
        ab.grace := 0;
        logs.info( source_ip & " tried a privileged login" );
     -- a service, like mysql, should not be publically accessible
     elsif kind = service_login then
        ab.grace := 0;
        logs.info( source_ip & " tried a service login" );
     elsif ab.grace > 0 then
        ab.grace := @-1;
     end if;

     if ab.grace = 0 then
        ab.sshd_blocked    := short_blocked;
        ab.sshd_offences := @+1;
     end if;
     if ab.sshd_offences > 0 then
        block( source_ip );
     end if;
     btree_io.set( offender_file, string( source_ip ), ab );
  else
     btree_io.get( offender_file, string( source_ip ), ab );
     -- TODO: logged_on is not a guarantee of uniqueness since there could
     -- be multiple attacks in a single second.  Also, this test only applies
     -- when reading the whole log file.  In daemon mode, we know all entries
     -- are new.
     if is_daemon or ab.logged_on < logged_on then
        if ab.sshd_blocked <= probation_blocked then
           if reason /= "" then
              logs.info( source_ip ) @ ( reason );
           end if;
           begin
             -- the speed of consecutive attacks from one IP (in seconds)
             freq := abs( numerics.value(string(ab.logged_on)) - numerics.value(string(logged_on)) );
           exception when others =>
              -- ab.logged_in may be occasionally blank such as when it was not
              -- correctly determined from the logs.  Assume these are
              -- malformed log entries and treat as a bot attack.
              freq := 0;
           end;
           ab.logged_on       := logged_on;
           ab.updated_on      := ts;

           -- If a two events occur in under 3 seconds, assume it is
           -- automated and block outright.  Otherwise, deduct grace.
           if freq <= 3 then
              ab.grace := 0;
              logs.info( source_ip & " looks like a bot because 2 violations logged in" & strings.image( freq ) & " second(s)" );
           -- calling card logins are automatically blocked
           elsif kind = calling_card then
              ab.grace := 0;
              logs.info( source_ip & " tried a calling card login" );
           -- privileged logins, if they exist, should not be publically accessible
           -- are automatically blocked
           elsif kind = privileged_login then
              ab.grace := 0;
              logs.info( source_ip & " tried a privileged login" );
           -- a service, like mysql, should not be publically accessible
           elsif kind = service_login then
              ab.grace := 0;
              logs.info( source_ip & " tried a service login" );
           elsif ab.grace > 0 then
              ab.grace := @-1;
           end if;

           -- If grace is exhausted, then block
           if ab.grace = 0 then
              ab.sshd_blocked_on := ts;
              ab.sshd_offences := @+1;
              if ab.sshd_offences > banned_threshhold then
                ab.sshd_blocked := banned_blocked;
              else
                ab.sshd_blocked := short_blocked;
              end if;
           else
              logs.info( source_ip & " has grace" );
           end if;
           btree_io.set( offender_file, string( source_ip ), ab );
           if ab.sshd_blocked > probation_blocked then
              msg := "";
              if ab.mail_blocked > probation_blocked then
                 msg := @ & " SMTP";
              end if;
              if ab.spam_blocked > probation_blocked then
                 msg := " SPAM";
              end if;
              if ab.http_blocked > probation_blocked then
                 msg := @ & " HTTP";
              end if;
              if msg /= "" then
                 logs.info( string( source_ip ) &
                   " SSHD offender already blocked for" & msg );
              else
                 logs.info( source_ip & " has no grace" );
                 block( source_ip );
              end if;
           end if;
        else
           -- here, it's already blocked.  determine how long from most recent
           -- blocking time.  If it's recent, it's just an info message.
           blocked_on := ab.sshd_blocked_on;
           if ab.mail_blocked_on > blocked_on then
              blocked_on := ab.mail_blocked_on;
           end if;
           if ab.spam_blocked_on > blocked_on then
              blocked_on := ab.spam_blocked_on;
           end if;
           if ab.http_blocked_on > blocked_on then
              blocked_on := ab.http_blocked_on;
           end if;
           -- we expect some delay while blocking takes effect.  If an IP is
           -- still not blocked after 5 minutes, try to re-block it
           --log_info( source_info.file ) @ ( ts ) @ ( " " ) @ ( blocked_on ); -- DEBUG   :1510869238  1510869836
           blocked_on := timestamp_string( strings.trim( strings.image( integer( numerics.value( string( blocked_on ) ) ) + 600 ) ) );
           if ts > blocked_on then
              logs.warning( "reblocking already blocked " & source_ip );
              block( source_ip );
           else
              logs.info( "already blocked " & source_ip );
           end if;
        end if;
     end if;
  end if;
  logs.level_end( old_log_level );
end sshd_record_and_block;


-- MAIL RECORD AND BLOCK
--
-- Record the offending IP number and block it with the configured firewall.
-- If it already has a record, update the existing record.
-----------------------------------------------------------------------------

procedure mail_record_and_block( source_ip : ip_string; logged_on : timestamp_string; ts : timestamp_string; is_daemon : boolean; reason : string ) is
  ab : an_offender;
  msg : string;
  blocked_on : timestamp_string;
  -- old_log_level : a_log_level := log_level_start;
  old_log_level : logs.log_level;
begin
  logs.level_begin( old_log_level );
  if not btree_io.has_element( offender_file, string( source_ip ) ) then
     if reason /= "" then
        logs.info( source_ip ) @ ( reason );
     end if;
     ab.source_ip       := source_ip;
     ab.source_name     := "";
     ab.source_country  := "";
     ab.location        := "";
     ab.sshd_blocked    := unblocked_blocked;
     ab.sshd_blocked_on := ts;
     ab.sshd_offences   := 0;
     ab.mail_blocked    := unblocked_blocked;
     ab.mail_blocked_on := ts;
     ab.mail_offences   := 0;
     ab.spam_blocked    := unblocked_blocked;
     ab.spam_blocked_on := ts;
     ab.spam_offences   := 0;
     ab.http_blocked    := unblocked_blocked;
     ab.http_blocked_on := ts;
     ab.http_offences   := 0;
     ab.grace           := mail_grace+1;
     ab.created_on      := ts;
     ab.updated_on      := ts;
     ab.data_type       := real_data;
     -- The logged date may be invalid.  Use the current time if it is.
     if strings.is_digit( logged_on ) then
        ab.logged_on := logged_on;
     else
        ab.logged_on := ts;
     end if;
     if ab.grace > 0 then
        ab.grace := @-1;
     end if;
     if ab.grace = 0 then
        ab.mail_blocked    := short_blocked;
        ab.mail_offences := @+1;
     else
        logs.info( source_ip & " has grace" );
     end if;
     if ab.mail_offences > 0 then
        block( source_ip );
     end if;
     btree_io.set( offender_file, string( source_ip ), ab );
  else
     btree_io.get( offender_file, string( source_ip ), ab );
     -- TODO: logged_on is not a guarantee of uniqueness since there could
     -- be multiple attacks in a single second.  Also, this test only applies
     -- when reading the whole log file.  In daemon mode, we know all entries
     -- are new.
     if is_daemon or ab.logged_on < logged_on then
        if ab.mail_blocked <= probation_blocked then
           if reason /= "" then
              logs.info( source_ip ) @ ( reason );
           end if;
           ab.logged_on       := logged_on;
           ab.updated_on      := ts;
           if ab.grace > 0 then
              ab.grace := @-1;
           end if;
           if ab.grace = 0 then
              ab.mail_blocked_on := ts;
              ab.mail_offences := @+1;
              if ab.mail_offences > banned_threshhold then
                ab.mail_blocked := banned_blocked;
              else
                ab.mail_blocked := short_blocked;
              end if;
           else
              logs.info( source_ip & " has grace" );
           end if;
           btree_io.set( offender_file, string( source_ip ), ab );
           if ab.mail_blocked > probation_blocked then
              msg := "";
              if ab.sshd_blocked > probation_blocked then
                 msg := " SSHD";
              end if;
              if ab.spam_blocked > probation_blocked then
                 msg := @ & " SPAM";
              end if;
              if ab.http_blocked > probation_blocked then
                 msg := @ & " HTTP";
              end if;
              if msg /= "" then
                 logs.info( string( source_ip ) &
                   " SMTP offender already blocked for" & msg );
              else
                 logs.info( source_ip & " has no grace" );
                 block( source_ip );
              end if;
           end if;
        else
           -- here, it's already blocked.  determine how long from most recent
           -- blocking time.  If it's recent, it's just an info message.
           blocked_on := ab.sshd_blocked_on;
           if ab.mail_blocked_on > blocked_on then
              blocked_on := ab.mail_blocked_on;
           end if;
           if ab.spam_blocked_on > blocked_on then
              blocked_on := ab.spam_blocked_on;
           end if;
           if ab.http_blocked_on > blocked_on then
              blocked_on := ab.http_blocked_on;
           end if;
           -- we expect some delay while blocking takes effect.  If an IP is
           -- still not blocked after 5 minutes, try to re-block it
           blocked_on := timestamp_string( strings.trim( strings.image( integer( numerics.value( string( blocked_on ) ) ) + 600 ) ) );
           if ts > blocked_on then
              logs.warning( "reblocking already blocked " & source_ip );
              block( source_ip );
           else
              logs.info( "already blocked " & source_ip );
           end if;
        end if;
     end if;
  end if;
  logs.level_end( old_log_level );
end mail_record_and_block;


-- SPAM RECORD AND BLOCK
--
-- Record the offending IP number and block it with the configured firewall.
-- If it already has a record, update the existing record.
-----------------------------------------------------------------------------

procedure spam_record_and_block( source_ip : ip_string; logged_on : timestamp_string; ts : timestamp_string; is_daemon : boolean; reason : string ) is
  ab : an_offender;
  msg : string;
  blocked_on : timestamp_string;
  -- old_log_level : a_log_level := log_level_start;
  old_log_level : logs.log_level;
begin
  logs.level_begin( old_log_level );
  if not btree_io.has_element( offender_file, string( source_ip ) ) then
     if reason /= "" then
        logs.info( source_ip ) @ ( reason );
     end if;
     ab.source_ip       := source_ip;
     ab.source_name     := "";
     ab.source_country  := "";
     ab.location        := "";
     ab.sshd_blocked    := unblocked_blocked;
     ab.sshd_blocked_on := ts;
     ab.sshd_offences   := 0;
     ab.mail_blocked    := unblocked_blocked;
     ab.mail_blocked_on := ts;
     ab.mail_offences   := 0;
     ab.spam_blocked    := unblocked_blocked;
     ab.spam_blocked_on := ts;
     ab.spam_offences   := 0;
     ab.http_blocked    := unblocked_blocked;
     ab.http_blocked_on := ts;
     ab.http_offences   := 0;
     ab.grace           := mail_grace+1;
     ab.created_on      := ts;
     ab.updated_on      := ts;
     ab.data_type       := real_data;
     -- The logged date may be invalid.  Use the current time if it is.
     if strings.is_digit( logged_on ) then
        ab.logged_on := logged_on;
     else
        ab.logged_on := ts;
     end if;
     if ab.grace > 0 then
        ab.grace := @-1;
     end if;
     if ab.grace = 0 then
        ab.spam_blocked  := short_blocked;
        ab.spam_offences := @+1;
     else
        logs.info( source_ip & " has grace" );
     end if;
     if ab.spam_offences > 0 then
        block( source_ip );
     end if;
     btree_io.set( offender_file, string( source_ip ), ab );
  else
     btree_io.get( offender_file, string( source_ip ), ab );
     -- TODO: logged_on is not a guarantee of uniqueness since there could
     -- be multiple attacks in a single second.  Also, this test only applies
     -- when reading the whole log file.  In daemon mode, we know all entries
     -- are new.
     if is_daemon or ab.logged_on < logged_on then
        if ab.spam_blocked <= probation_blocked then
           if reason /= "" then
              logs.info( source_ip ) @ ( reason );
           end if;
           ab.logged_on       := logged_on;
           ab.updated_on      := ts;
           if ab.grace > 0 then
              ab.grace := @-1;
           end if;
           if ab.grace = 0 then
              ab.spam_blocked_on := ts;
              ab.spam_offences := @+1;
              if ab.spam_offences > banned_threshhold then
                ab.spam_blocked := banned_blocked;
              else
                ab.spam_blocked := short_blocked;
              end if;
           else
             logs.info( source_ip & " has grace" );
           end if;
           btree_io.set( offender_file, string( source_ip ), ab );
           if ab.spam_blocked > probation_blocked then
              msg := "";
              if ab.sshd_blocked > probation_blocked then
                 msg := " SSDH";
              end if;
              if ab.mail_blocked > probation_blocked then
                 msg := @ & " SMTP";
              end if;
              if ab.http_blocked > probation_blocked then
                 msg := @ & " HTTP";
              end if;
              if msg /= "" then
                 logs.info( string( source_ip ) &
                   " SPAM offender already blocked for" & msg );
              else
                 logs.info( source_ip & " has no grace" );
                 block( source_ip );
              end if;
           end if;
        else
           -- here, it's already blocked.  determine how long from most recent
           -- blocking time.  If it's recent, it's just an info message.
           blocked_on := ab.sshd_blocked_on;
           if ab.mail_blocked_on > blocked_on then
              blocked_on := ab.mail_blocked_on;
           end if;
           if ab.spam_blocked_on > blocked_on then
              blocked_on := ab.spam_blocked_on;
           end if;
           if ab.http_blocked_on > blocked_on then
              blocked_on := ab.http_blocked_on;
           end if;
           -- we expect some delay while blocking takes effect.  If an IP is
           -- still not blocked after 5 minutes, try to re-block it
           blocked_on := timestamp_string( strings.trim( strings.image( integer( numerics.value( string( blocked_on ) ) ) + 600 ) ) );
           if ts > blocked_on then
              logs.warning( "reblocking already blocked " & source_ip );
              block( source_ip );
           else
              logs.info( "already blocked " & source_ip );
           end if;
        end if;
     end if;
  end if;
  logs.level_end( old_log_level );
end spam_record_and_block;


-- HTTP RECORD AND BLOCK
--
-- Record the offending IP number and block it with the configured firewall.
-- If it already has a record, update the existing record.
-----------------------------------------------------------------------------

procedure http_record_and_block( source_ip : ip_string; logged_on : timestamp_string; ts : timestamp_string; is_daemon : boolean; reason : string ) is
  ab : an_offender;
  msg : string;
  blocked_on : timestamp_string;
  -- old_log_level : a_log_level := log_level_start;
  old_log_level : logs.log_level;
begin
  logs.level_begin( old_log_level );
  if not btree_io.has_element( offender_file, string( source_ip ) ) then
     if reason /= "" then
        logs.info( source_ip ) @ ( reason );
     end if;
     ab.source_ip       := source_ip;
     ab.source_name     := "";
     ab.source_country  := "";
     ab.location        := "";
     ab.sshd_blocked    := unblocked_blocked;
     ab.sshd_blocked_on := ts;
     ab.sshd_offences   := 0;
     ab.mail_blocked    := unblocked_blocked;
     ab.mail_blocked_on := ts;
     ab.mail_offences   := 0;
     ab.spam_blocked    := unblocked_blocked;
     ab.spam_blocked_on := ts;
     ab.spam_offences   := 0;
     ab.http_blocked    := unblocked_blocked;
     ab.http_blocked_on := ts;
     ab.http_offences   := 0;
     ab.grace           := default_grace+1;
     ab.created_on      := ts;
     ab.updated_on      := ts;
     ab.data_type       := real_data;
     -- The logged date may be invalid.  Use the current time if it is.
     if strings.is_digit( logged_on ) then
        ab.logged_on := logged_on;
     else
        ab.logged_on := ts;
     end if;
     if ab.grace > 0 then
        ab.grace := @-1;
     end if;
     if ab.grace = 0 then
        ab.http_blocked    := short_blocked;
        ab.http_offences := @+1;
     else
        logs.info( source_ip & " has grace" );
     end if;
     if ab.http_offences > 0 then
        block( source_ip );
     end if;
     btree_io.set( offender_file, string( source_ip ), ab );
  else
     btree_io.get( offender_file, string( source_ip ), ab );
     -- TODO: logged_on is not a guarantee of uniqueness since there could
     -- be multiple attacks in a single second.  Also, this test only applies
     -- when reading the whole log file.  In daemon mode, we know all entries
     -- are new.
     if is_daemon or ab.logged_on < logged_on then
        if ab.http_blocked <= probation_blocked then
           if reason /= "" then
              logs.info( source_ip ) @ ( reason );
           end if;
           ab.logged_on       := logged_on;
           ab.updated_on      := ts;
           if ab.grace > 0 then
              ab.grace := @-1;
           end if;
           if ab.grace = 0 then
              ab.http_blocked_on := ts;
              ab.http_offences := @+1;
              if ab.http_offences > banned_threshhold then
                ab.http_blocked := banned_blocked;
              else
                ab.http_blocked := short_blocked;
              end if;
           else
              logs.info( source_ip & " has grace" );
           end if;
           btree_io.set( offender_file, string( source_ip ), ab );
           if ab.http_blocked > probation_blocked then
              msg := "";
              if ab.sshd_blocked > probation_blocked then
                 msg := @ & " SSHD";
              end if;
              if ab.mail_blocked > probation_blocked then
                 msg := @ & " SMTP";
              end if;
              if ab.spam_blocked > probation_blocked then
                 msg := " SPAM";
              end if;
              if msg /= "" then
                 logs.info( string( source_ip ) &
                   " HTTP offender already blocked for" & msg );
              else
                 logs.info( source_ip & " has no grace" );
                 block( source_ip );
              end if;
           end if;
        else
           -- here, it's already blocked.  determine how long from most recent
           -- blocking time.  If it's recent, it's just an info message.
           blocked_on := ab.sshd_blocked_on;
           if ab.mail_blocked_on > blocked_on then
              blocked_on := ab.mail_blocked_on;
           end if;
           if ab.spam_blocked_on > blocked_on then
              blocked_on := ab.spam_blocked_on;
           end if;
           if ab.http_blocked_on > blocked_on then
              blocked_on := ab.http_blocked_on;
           end if;
           -- we expect some delay while blocking takes effect.  If an IP is
           -- still not blocked after 5 minutes, try to re-block it
           blocked_on := timestamp_string( strings.trim( strings.image( integer( numerics.value( string( blocked_on ) ) ) + 600 ) ) );
           if ts > blocked_on then
              logs.warning( "reblocking already blocked " & source_ip );
              block( source_ip );
           else
              logs.info( "already blocked " & source_ip );
           end if;
        end if;
     end if;
  end if;
  logs.level_end( old_log_level );
end http_record_and_block;


-- FOREIGN RECORD AND BLOCK
--
-- Record the offending IP number from a third-party source and
-- and block it with the configured firewall.  Do not provide grace.
-- If we already seen it, don't add it again.
-----------------------------------------------------------------------------

procedure foreign_record_and_block( source_ip : ip_string; logged_on : timestamp_string; ts : timestamp_string; reason : string ) is
  ab : an_offender;
  old_log_level : logs.log_level;
begin
  logs.level_begin( old_log_level );
  if not btree_io.has_element( offender_file, string( source_ip ) ) then
     if reason /= "" then
        logs.info( source_ip ) @ ( " " ) @ ( reason );
     end if;
     ab.source_ip       := source_ip;
     ab.source_name     := "";
     ab.source_country  := "";
     ab.location        := "";
     ab.sshd_blocked    := banned_blocked;
     ab.sshd_blocked_on := ts;
     ab.sshd_offences   := banned_threshhold;
     ab.mail_blocked    := banned_blocked;
     ab.mail_blocked_on := ts;
     ab.mail_offences   := banned_threshhold;
     ab.spam_blocked    := banned_blocked;
     ab.spam_blocked_on := ts;
     ab.spam_offences   := banned_threshhold;
     ab.http_blocked    := banned_blocked;
     ab.http_blocked_on := ts;
     ab.http_offences   := banned_threshhold;
     ab.grace           := 0;
     ab.created_on      := ts;
     ab.logged_on       := logged_on;
     ab.updated_on      := ts;
     ab.data_type       := real_data;
     ab.sourced_from    := reason;
     btree_io.set( offender_file, string( source_ip ), ab );
  end if;
  logs.level_end( old_log_level );
end foreign_record_and_block;


-- NUMBER BLOCKED
--
-- The number of IP addresses currently blocked, or 999999 on an error.
-----------------------------------------------------------------------------

function number_blocked return natural is
  total_str : string;
  tmp_total : natural := 999999;
  total : natural := 999999;
begin
  total_str := `/sbin/ipset -L blocklist | wc -l;`;
  if $? /= 0 then
     logs.error( "ipset did not run" );
  elsif total_str /= "" then
     begin
        tmp_total := numerics.value( total_str );
     exception when others =>
        null;
     end;
     if tmp_total < 7 then
        logs.error("ipset results unexpectedly short: " & strings.to_escaped( total_str ) );
     else
        total := tmp_total-7;
     end if;
  end if;
  return total;
end number_blocked;


-- REBLOCK ALL
--
-- Go through the blocking history and reblock all IP's that should be
-- blocked already.  That is, anything that is long-term or permanently
-- blocked.  Does not automatically block imported blocks from other systems.
-- This is used when resetting the firewall.
-----------------------------------------------------------------------------

function reblock_all return natural is
  offender_cursor : btree_io.cursor( an_offender );
  offender_key : string;
  offender : an_offender;
  offender_json : json_string;
  block_count : natural := 0;
begin
  btree_io.open( offender_file, string( offender_path ), offender_buffer_width, offender_buffer_width );
  btree_io.open_cursor( offender_file, offender_cursor );
  btree_io.get_first( offender_file, offender_cursor, offender_key, offender );
  loop
     records.to_json( offender_json, offender );
     if (offender.sshd_blocked > short_blocked or
        offender.mail_blocked > short_blocked or
        offender.http_blocked > short_blocked or
        offender.spam_blocked > short_blocked) and
        offender.sourced_from = "" then
        block( offender.source_ip );
        block_count := @ + 1;
     end if;
     btree_io.get_next( offender_file, offender_cursor, offender_key, offender );
  end loop;
  return block_count;
exception when others =>
  put_line( "blocked " & strings.image( block_count ) );
  if btree_io.is_open( offender_file ) then
     btree_io.close_cursor( offender_file, offender_cursor );
     btree_io.close( offender_file );
  end if;
  return block_count;
end reblock_all;

------------------------------------------------------------------------------
-- Housekeeping
------------------------------------------------------------------------------


-- STARTUP BLOCKING
--
-- Open or create the blocked ip file.
-----------------------------------------------------------------------------

procedure startup_blocking is
begin
   if files.exists( string( offender_path ) ) then
      btree_io.open( offender_file, string( offender_path ), offender_buffer_width, offender_buffer_width );
   else
      btree_io.create( offender_file, string( offender_path ), offender_buffer_width, offender_buffer_width );
   end if;
end startup_blocking;


-- SHUTDOWN BLOCKING
--
-- Open or create the blocked ip file.
-----------------------------------------------------------------------------
procedure shutdown_blocking is
begin
  if btree_io.is_open( offender_file ) then
     btree_io.close( offender_file );
  end if;
end shutdown_blocking;

-- vim: ft=spar
