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
       IPSET_CMD( "-q", "test", "blocklist", offender );
       if $? /= 0 then
          IPSET_CMD( "add", "blocklist", offender );
       end if;
     when iptables_old_firewall =>
       IPTABLES_CMD( "-I", "INPUT",  "1", "-s", offender, "-j", "DROP" );
       IPTABLES_CMD( "-I", "OUTPUT", "1", "-d", offender, "-j", "REJECT" );
     when firewalld_firewall =>
       FIREWALL_CMD( "--zone=public", "--add-rich-rule=" & ASCII.Quotation & "rule family='ipv4' source address='$offender'" & ASCII.Quotation & " drop" );
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
       IPSET_CMD( "-q", "test", "blocklist", offender );
       if $? = 0 then
          IPSET_CMD( "del", "blocklist", offender );
          if os.status = 0 then
             log_info( source_info.source_location ) @ ( "unblocked " & offender );
          else
             log_error( source_info.source_location ) @ ( "error" & strings.image( os.status ) & " on unblocking " & offender );
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
  -- Record the blocked ip
end unblock;

-- CLEAR FIREWALL
--
-----------------------------------------------------------------------------

procedure clear_firewall is

  procedure clear_iptables is
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

    -- This is a restrictive firewall.
    -- https://wiki.centos.org/HowTos/Network/IPTables
    -- TODO: This could likely be made fancier...
    IPTABLES_CMD( "-P", "INPUT", "ACCEPT" );
    IPTABLES_CMD( "-F" );
    IPTABLES_CMD( "-A", "INPUT", "-i", "lo", "-j", "ACCEPT" );
    IPTABLES_CMD( "-A", "INPUT", "-m", "state", "--state",
      "ESTABLISHED,RELATED", "-j", "ACCEPT" );
    IPTABLES_CMD( "-A", "INPUT", "-p", "tcp", "--dport", "22", "-j",
      "ACCEPT" );
    IPTABLES_CMD( "-P", "INPUT", "DROP" );
    IPTABLES_CMD( "-P", "FORWARD", "DROP" );
    IPTABLES_CMD( "-P", "OUTPUT", "ACCEPT" );

    log_info( source_info.source_location ) @ ( "iptables cleared " );
  end clear_iptables;

begin
  if mode /= monitor_mode and mode /= honeypot_mode then
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
        IPSET_CMD( "-q", "list", "blocklist" ) ;
        --ipset -q list blocklist >/dev/null 2>/dev/null ;
        if $? /= 0 then
           clear_iptables;
           IPSET_CMD( "create", "blocklist", "iphash" );
           IPTABLES_CMD( "-A", "INPUT", "-m", "set", "--match-set", "blocklist", "src",
             "-j", "DROP" ) ;
           IPTABLES_CMD( "-A", "INPUT", "-m", "set", "--match-set", "blocklist",  "dst",
             "-j", "REJECT" ) ;
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
end clear_firewall;


-- RESET FIREWALL
--
-- Clear the firewall rules and restore the current state.
-----------------------------------------------------------------------------

procedure reset_firewall is
begin
  clear_firewall;

  -- Block services
  case firewall_kind is
  when iptables_firewall | iptables_old_firewall =>
     -- These are hard-coded for testing.  No logging active.
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
     IPTABLES_CMD( "-A", "INPUT", "-p", "tcp", "--destination-port", "8080", "-j", "ACCEPT" );
     --IPTABLES_CMD( "-A", "INPUT", "-p", "tcp", "--destination-port", "11212", "-j", "REJECT" );
     --IPTABLES_CMD( "-A", "INPUT", "-p", "tcp", "--destination-port", "11211", "-j", "REJECT" );
     --IPTABLES_CMD( "-A", "INPUT", "-p", "tcp", "--destination-port", "11212", "-j", "REJECT" );
  when others =>
     put_line( standard_error, "not implemented yet" );
  end case;

  -- TODO: restore the current state of blocked offenders

end reset_firewall;

-- vim: ft=spar
