separate;

IPSET_CMD    : constant command := "/sbin/ipset";
IPTABLES_CMD : constant command := "/sbin/iptables";
FIREWALL_CMD : constant command := "/bin/firewall-cmd";


-- BLOCK
--
-----------------------------------------------------------------------------

procedure block( offender : ip_string ) is
begin
  if mode = monitor_mode then
     log_info( source_info.source_location ) @ ( "would have blocked " & offender );
  else
     case firewall_kind is
     when iptables_firewall =>
       IPSET_CMD( "add", "blocklist", offender );
     when iptables_old_firewall =>
       IPTABLES_CMD( "-I", "INPUT",  "1", "-s", offender, "-j", "DROP" );
       IPTABLES_CMD( "-I", "OUTPUT", "1", "-d", offender, "-j", "REJECT" );
     when firewalld_firewall =>
       FIREWALL_CMD( "--zone=public", "--add-rich-rule='rule family='ipv4' source address='$offender' drop" );
     when suse_firewall =>
        put_line( standard_error, "error - not implemented yet" );
     when others =>
        put_line( standard_error, "error - unexpected firewall type" );
     end case;

     if os.status = 0 then
        log_info( source_info.source_location ) @ ( "blocked " & offender );
     else
        put_line( standard_error, "error " & strings.image( os.status ) & " on blocking " & offender );
     end if;
  end if;
  -- Record the blocked ip
end block;

-- UNBLOCK
--
-----------------------------------------------------------------------------

procedure unblock( offender : ip_string ) is
begin
  if mode = monitor_mode then
     log_info( source_info.source_location ) @ ( "would have unblocked " & offender );
  else
     case firewall_kind is
     when iptables_firewall =>
       IPSET_CMD( "del", "blocklist", offender );
     when iptables_old_firewall =>
       null;
     when firewalld_firewall =>
       null;
     when suse_firewall =>
       null;
     when others =>
        put_line( standard_error, "error - unexpected firewall type" );
     end case;

     if os.status = 0 then
        log_info( source_info.source_location ) @ ( "unblocked " & offender );
     else
        put_line( standard_error, "error " & strings.image( os.status ) & " on unblocking " & offender );
     end if;
  end if;
  -- Record the blocked ip
end unblock;


-- CLEAR FIREWALL
--
-----------------------------------------------------------------------------

procedure clear_firewall is
begin
  case firewall_kind is
  when iptables_firewall =>
    IPSET_CMD( "flush", "-q", "list", "blocklist" );
  when iptables_old_firewall =>
    IPTABLES_CMD( "-F" );
    IPTABLES_CMD( "-X" );
    IPTABLES_CMD( "-t", "nat", "-F" );
    IPTABLES_CMD( "-t", "nat", "-X" );
    IPTABLES_CMD( "-t", "mangle", "-F" );
    IPTABLES_CMD( "-t", "mangle", "-X" );
    IPTABLES_CMD( "-P", "INPUT", "ACCEPT" );
    IPTABLES_CMD( "-P", "FORWARD", "ACCEPT" );
    IPTABLES_CMD( "-P", "OUTPUT", "ACCEPT" );
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
  process_blacklist;
end clear_firewall;


-- RESET FIREWALL
--
-- Clear the firewall rules and restore the current state.
-----------------------------------------------------------------------------

procedure reset_firewall is
begin
  clear_firewall;
  -- TODO: restore the current state
end reset_firewall;

-- vim: ft=spar
