#!/usr/local/bin/spar

procedure wash_blocked is
  pragma annotate( summary, "wash_blocked" )
                @( description, "Update blocked IP details and unblock " )
                @( description, "IP numbers." )
                @( author, "Ken O. Burtch" );
  pragma license( gplv3 );
  pragma software_model( shell_script );

  with separate "config/contributors.inc.sp";
  with separate "lib/world.inc.sp";
  with separate "config/config.inc.sp";
  with separate "lib/common.inc.sp";
  with separate "lib/blocking.inc.sp";
  with separate "lib/countries.inc.sp";

  pragma annotate( todo, "GeoIP should probably be moved to central server so it doesn't have to be install" );

  -- These types are not used here.  As a workaround,
  -- mark them used.  Until this is sorted out.

  pragma assumption( applied, country_data );
  pragma assumption( applied, comment_string );

  months_3 : constant natural := 60*60*24*30*3;
  weeks_1  : constant natural := 60*60*24*7;
  hours_1  : constant natural := 60*60;

     --put_line( `ping -c 1 -W 5 "$sip" | head -2 ;` );
     --source_host := `ping -c 1 -W 5 "$sip" | head -2 | tail -1 | cut -c15- | cut -d' ' -f1 ;`;
     --if source_host = dns_string( sip ) & ":" then
     -- host may not be installed but ping always is...


-- IS ASIAN IP
--
--  True if IP number is in ranges handled by APNIC (Asia-Pacific NIC)
--  http://collaboration.cmc.ec.gc.ca/science/rpn/biblio/ddj/Website/articles/SA/v14/i11/a3.htm
------------------------------------------------------------------------------

function is_asian_ip( source_ip : ip_string ) return boolean is
  ip3 : ip_string;
  ip4 : ip_string;
  ip8 : ip_string;
  apnic : boolean := false;
begin
  ip3 := ip_string( strings.slice( source_ip, 1, 3 ) );
  ip4 := ip_string( strings.slice( source_ip, 1, 4 ) );
  ip8 := ip_string( strings.slice( source_ip, 1, 8 ) );

  if ip3 = "58." then
    apnic;
  elsif ip3 = "61." then
    apnic;
  elsif ip4 = "126." then
    apnic;
  elsif ip8 = "168.208." then
    apnic;
  elsif ip8 = "196.192." then
    apnic;
  elsif ip4 = "202." then
    apnic;
  elsif ip4 = "210." then
    apnic;
  elsif ip4 = "218." then
    apnic;
  elsif ip4 = "220." then
    apnic;
  elsif ip4 = "222." then
    apnic;
  end if;

  return apnic;
end is_asian_ip;

-- IS RUSSIAN IP
--
-- True if IP number is in ranges handled by RIPE (Russia, Hungary, etc. NIC)
-- http://collaboration.cmc.ec.gc.ca/science/rpn/biblio/ddj/Website/articles/SA/v14/i11/a3.htm
----------------------------------------------------------------------------

function is_russian_ip( source_ip : ip_string ) return boolean is
  ip3 : ip_string;
  ip4 : ip_string;
  ripe : boolean := false;
begin
  ip3 := ip_string( strings.slice( source_ip, 1, 3 ) );
  ip4 := ip_string( strings.slice( source_ip, 1, 4 ) );

  if ip3   = "80." then
    ripe;
  elsif ip3 = "81." then
    ripe;
  elsif ip3 = "82." then
    ripe;
  elsif ip3 = "83." then
    ripe;
  elsif ip3 = "84." then
    ripe;
  elsif ip3 = "85." then
    ripe;
  elsif ip3 = "86." then
    ripe;
  elsif ip3 = "87." then
    ripe;
  elsif ip3 = "88." then
    ripe;
  elsif ip3 = "89." then
    ripe;
  elsif ip3 = "90." then
    ripe;
  elsif ip3 = "91." then
    ripe;
  elsif ip4 = "193." then
    ripe;
  elsif ip4 = "194." then
    ripe;
  elsif ip4 = "195." then
    ripe;
  elsif ip4 = "212." then
    ripe;
  elsif ip4 = "213." then
    ripe;
  elsif ip4 = "217." then
    ripe;
  end if;

  return ripe;
end is_russian_ip;

-- SAMERICAN IP
--
-- True if IP number is in ranges handled by LACNIC (Latin American and Caribbean NIC)
-- Includes Brazil, Argentina but also Mexico, etc.
-- http://collaboration.cmc.ec.gc.ca/science/rpn/biblio/ddj/Website/articles/SA/v14/i11/a3.htm
----------------------------------------------------------------------------

function is_south_american_ip( source_ip : ip_string ) return boolean is
  ip4 : ip_string;
  lacnic : boolean := false;
begin
  ip4 := ip_string( strings.slice( source_ip, 1, 4 ) );

  if    ip4 = "189." then
    lacnic;
  elsif  ip4 = "190." then
    lacnic;
  elsif  ip4 = "200." then
    lacnic;
  elsif  ip4 = "201." then
    lacnic;
  end if;

  return lacnic;
end is_south_american_ip;

  --abt : btree_io.file( a_blocked_ip );
  abtc : btree_io.cursor( an_offender );
  key : string;
  source_ip : an_offender;
  j : json_string;
  source_host : dns_string;
  source_country : country_string;
  source_location : string;
  sip  : ip_string;

  procedure search_ipinfo( ip : ip_string; country : out country_string; location : out string ) is
    type ipinfo_reply is record
      city   : string;
      region : string;
      country: country_string;
    end record;
    ipinfo : ipinfo_reply;
    j : json_string;
  begin
    -- TODO: this relies on an internet service
    -- The return format varies....we strip here common fields we want.
    -- there is a lookup limit, 1000 requests/day
    -- TODO: there is a GeoIP database for CentOS...how do you access it?
    j := `curl -s "ipinfo.io/$sip" | grep 'city\|region\|country' ;`;
    if strings.element( string( j ), strings.length( j ) ) = "," then
       j := json_string( strings.delete( string( j ), strings.length( j ), strings.length( j ) ) );
    end if;
    j := "{" & j & "}";
    records.to_record( ipinfo, j );
    country := ipinfo.country;
    if ipinfo.city = ipinfo.region then
       location := ipinfo.city & "," & string( ipinfo.country );
    else
       location := ipinfo.city & "," & ipinfo.region & "," & string( ipinfo.country );
    end if;
  end search_ipinfo;

  -- https://freegeoip.net/json/78.196.118.157
  procedure search_freegeoip( ip : ip_string; country : out country_string; location : out string ) is
    type freegeoip_reply is record
      city         : string;
      region_name  : string;
      --country_name : country_string;
      country_code : country_string;
    end record;
    freegeoip : freegeoip_reply;
    j : json_string;
  begin
    -- TODO: this relies on an internet service
    -- The return format varies....we strip here common fields we want.
    -- there is a lookup limit, 15000 requests/day
    j := `curl -s "https://freegeoip.net/json/$sip" | grep 'city\|region_name\|country_name' ;`;
    if strings.element( string( j ), strings.length( j ) ) = "," then
       j := json_string( strings.delete( string( j ), strings.length( j ), strings.length( j ) ) );
    end if;
    j := "{" & j & "}";
    records.to_record( freegeoip, j );
    country := freegeoip.country_code;
    if freegeoip.city = freegeoip.region_name then
       location := freegeoip.city & "," & string( freegeoip.country_code );
    else
       location := freegeoip.city & "," & freegeoip.region_name & "," & string( freegeoip.country_code );
    end if;
  end search_freegeoip;


  -- GeoIP Database (Maxmind)
  --
  -- GeoIP Country Edition: US, United States
  -- GeoIP City Edition, Rev 1: US, TX, Texas, Dallas, 75245, 32.783100, -96.806702, 623, 214
  -- GeoIP ASNum Edition: AS63949 Linode, LLC

  procedure search_geoip( ip : ip_string; country : out country_string; location : out string ) is
     geoip_info : string;
     tmp : string;
  begin
     country := "";
     location := "";
     geoip_info := `geoiplookup "$ip";`;
     tmp := `echo "$geoip_info" | fgrep "Country Edition";`;
     tmp := strings.field( tmp, 2, ":" );
     country := country_string( strings.field( tmp, 1, "," ) );
     country := country_string( strings.trim( string( @ ) ) );
     if strings.length( country ) /= 2 then
        country := "";
     end if;
     tmp := `echo "$geoip_info" | fgrep "City Edition";`;
     location := strings.field( tmp, 2, ":" );
     location := strings.trim( @ );
     if strings.index( location, " not found" ) > 0 then
        if is_asian_ip( ip ) then
           location := "unknown asian source";
        elsif is_russian_ip( ip ) then
           location := "unknown russian source";
        elsif is_south_american_ip( ip ) then
           location := "unknown south american source";
        else
           location := "unknown source";
        end if;
     end if;
  end search_geoip;

  -- NUMBER BLOCKED
  --
  -- The number of IP addresses currently blocked, or 999999 on an error.

  function number_blocked return natural is
    total_str : string;
    total : natural := 999999;
  begin
    total_str := `/sbin/ipset -L blocklist | wc -l;`;
    if $? /= 0 then
       log_error( source_info.source_location ) @ ( "ipset did not run" );
    end if;
    if total_str /= "" then
       total := numerics.value( total_str );
       total := @-7;
    end if;
    return total;
  end number_blocked;


  -- Health Check
  --
  -- Verify the blockers are running.  Doesn't check the tail's.

  procedure health_check is
    tmp : string;
  begin
    tmp := `ps -ef;`;
    if strings.index( tmp, "http_blocker" ) = 0 then
        log_error( source_info.source_location ) @ ( "http blocker is not running" );
    end if;
    if strings.index( tmp, "mail_blocker" ) = 0 then
        log_error( source_info.source_location ) @ ( "mail blocker is not running" );
    end if;
    if strings.index( tmp, "sshd_blocker" ) = 0 then
        log_error( source_info.source_location ) @ ( "sshd blocker is not running" );
    end if;
  end health_check;

  this_run_on : timestamp_string;
  proposed_blocked_until : timestamp_string;
  blocked_until : timestamp_string;
  needs_updating : boolean := false;
  processing_cnt : natural := 0;
  updating_cnt   : natural := 0;
  pos : natural;

begin
  --setupWorld( "Wash Task", "log/wash.log" );
  setupWorld( "Wash Task", "log/blocker.log" );

  this_run_on := get_timestamp;

  health_check;

  startup_blocking;
  btree_io.open_cursor( offender_file, abtc );
  btree_io.get_first( offender_file, abtc, key, source_ip );
  loop
     processing_cnt := @+1;
     sip := source_ip.source_ip;
     if source_ip.source_name = "" then
        source_host := `host -W 5 "$sip";`;
        -- This potentally returns muliple entries.  Just use the last one.
        pos := index_reverse( string( source_host ), ASCII.LF );
        if pos > 0 then
           source_host := dns_string( strings.tail( string( source_host ),
              strings.length( source_host ) - pos ) );
        end if;
        if strings.index( source_host, "not found" ) > 0 then
           source_host := "";
        elsif strings.index( source_host, "timed out" ) > 0 then
           source_host := "";
        elsif source_host = "." or source_host = "no-data." then
           source_host := "";
        else
           -- TODO: strings.field
           source_host := `echo "$source_host" | cut -d' ' -f 5 ;`;
        end if;
        if source_host = "" then
           source_host := "unknown";
        end if;
        -- search_ipinfo( sip, source_country, source_location );
        search_geoip( sip, source_country, source_location );
        source_ip.source_name := source_host;
        source_ip.source_country := source_country;
        source_ip.location := source_location;
        log_info( source_info.source_location ) @ ( sip & " updated for dns and geo location" );
        needs_updating;
     end if;

     blocked_until := "";
     case source_ip.sshd_blocked is
     when banned_blocked =>
          proposed_blocked_until :=
            timestamp_string(
              strings.trim(
                strings.image(
                  integer( numerics.value( string( source_ip.sshd_blocked_on ) ) ) +
                    weeks_1 * source_ip.sshd_offenses )
             )
          );
          if this_run_on > proposed_blocked_until then
             source_ip.sshd_blocked := probation_blocked;
             needs_updating;
          end if;
          if proposed_blocked_until > blocked_until then
             blocked_until := proposed_blocked_until;
          end if;
     when short_blocked =>
          proposed_blocked_until :=
            timestamp_string(
              strings.trim(
                strings.image(
                  integer( numerics.value( string( source_ip.sshd_blocked_on ) ) ) +
                    hours_1 * source_ip.sshd_offenses )
             )
          );
          if this_run_on > proposed_blocked_until then
             source_ip.sshd_blocked := probation_blocked;
             needs_updating;
          end if;
          if proposed_blocked_until > blocked_until then
             blocked_until := proposed_blocked_until;
          end if;
     when probation_blocked => null;
     when others => null;
     end case;

     case source_ip.smtp_blocked is
     when banned_blocked =>
          proposed_blocked_until :=
            timestamp_string(
              strings.trim(
                strings.image(
                  integer( numerics.value( string( source_ip.smtp_blocked_on ) ) ) +
                    weeks_1 * source_ip.smtp_offenses )
             )
          );
          if this_run_on > proposed_blocked_until then
             source_ip.smtp_blocked := probation_blocked;
             needs_updating;
          end if;
          if proposed_blocked_until > blocked_until then
             blocked_until := proposed_blocked_until;
          end if;
     when short_blocked =>
          proposed_blocked_until :=
            timestamp_string(
              strings.trim(
                strings.image(
                  integer( numerics.value( string( source_ip.smtp_blocked_on ) ) ) +
                    hours_1 * source_ip.smtp_offenses )
             )
          );
          if this_run_on > proposed_blocked_until then
             source_ip.smtp_blocked := probation_blocked;
             needs_updating;
          end if;
          if proposed_blocked_until > blocked_until then
             blocked_until := proposed_blocked_until;
          end if;
     when probation_blocked => null;
     when others => null;
     end case;

     case source_ip.spam_blocked is
     when banned_blocked =>
          proposed_blocked_until :=
            timestamp_string(
              strings.trim(
                strings.image(
                  integer( numerics.value( string( source_ip.spam_blocked_on ) ) ) +
                    weeks_1 * source_ip.spam_offenses )
             )
          );
          if this_run_on > proposed_blocked_until then
             source_ip.spam_blocked := probation_blocked;
             needs_updating;
          end if;
          if proposed_blocked_until > blocked_until then
             blocked_until := proposed_blocked_until;
          end if;
     when short_blocked =>
          proposed_blocked_until :=
            timestamp_string(
              strings.trim(
                strings.image(
                  integer( numerics.value( string( source_ip.spam_blocked_on ) ) ) +
                    hours_1 * source_ip.spam_offenses )
             )
          );
          if this_run_on > proposed_blocked_until then
             source_ip.spam_blocked := probation_blocked;
             needs_updating;
          end if;
          if proposed_blocked_until > blocked_until then
             blocked_until := proposed_blocked_until;
          end if;
     when probation_blocked => null;
     when others => null;
     end case;

     case source_ip.http_blocked is
     when banned_blocked =>
          proposed_blocked_until :=
            timestamp_string(
              strings.trim(
                strings.image(
                  integer( numerics.value( string( source_ip.http_blocked_on ) ) ) +
                    weeks_1 * source_ip.http_offenses )
             )
          );
          if this_run_on > proposed_blocked_until then
             source_ip.http_blocked := probation_blocked;
             needs_updating;
          end if;
          if proposed_blocked_until > blocked_until then
             blocked_until := proposed_blocked_until;
          end if;
     when short_blocked =>
          proposed_blocked_until :=
            timestamp_string(
              strings.trim(
                strings.image(
                  integer( numerics.value( string( source_ip.http_blocked_on ) ) ) +
                    hours_1 * source_ip.http_offenses )
             )
          );
          if this_run_on > proposed_blocked_until then
             source_ip.http_blocked := probation_blocked;
             needs_updating;
          end if;
          if proposed_blocked_until > blocked_until then
             blocked_until := proposed_blocked_until;
          end if;
     when probation_blocked => null;
     when others => null;
     end case;

     -- Check and remove old records

     if not needs_updating then
          proposed_blocked_until :=
            timestamp_string(
              strings.trim(
                strings.image(
                  integer( numerics.value( string( source_ip.updated_on ) ) ) +
                    months_3 )
             )
          );
          -- TODO: might be better if this was pre-calculated
          if this_run_on > proposed_blocked_until then
             btree_io.remove( offender_file, key );
             log_info( source_info.source_location ) @ ( sip & " removed" );
          end if;
     else -- needs updating
        -- If some aspect has gone probationary and if the worst block
        -- has expired, then mark the IP number as probationary.
        if blocked_until /= "" then
           if this_run_on > blocked_until then
              log_info( source_info.source_location ) @ ( sip & " on probation" );
              unblock( sip );
           end if;
        end if;

        updating_cnt := @+1;
        needs_updating := false;
        source_ip.updated_on := this_run_on;
        begin
           btree_io.set( offender_file, key, source_ip );
        exception when others =>
           log_error( source_info.source_location )
                   @( exceptions.exception_info );
        end;
        -- TODO: do I need this next line?
        btree_io.get( offender_file, key, source_ip );
     end if;
     btree_io.raise_exceptions( offender_file, false );
     btree_io.get_next( offender_file, abtc, key, source_ip );
     exit when btree_io.last_error( offender_file ) = bdb.DB_NOTFOUND;
     btree_io.raise_exceptions( offender_file, true );
  end loop;
  btree_io.close_cursor( offender_file, abtc );
  shutdown_blocking;
  log_info( source_info.source_location ) @
     ( "Processed" ) @ ( strings.image( processing_cnt ) ) @ ( " blocking records" ) @
     ( "; Updated" ) @ ( strings.image( updating_cnt ) ) @
     ( "; Still blocked" ) @ ( strings.image( number_blocked ) );
  shutdownWorld;
exception when others =>
  if btree_io.is_open( offender_file ) then
     btree_io.close_cursor( offender_file, abtc );
  end if;
  shutdown_blocking;
  shutdownWorld;
end wash_blocked;

-- vim: ft=spar
