#!/usr/local/bin/spar

with separate "config/contributors.inc.sp";
with separate "lib/world.inc.sp";
with separate "config/config.inc.sp";

procedure wash_blocked is
  pragma annotate( summary, "wash_blocked" )
                @( description, "Update blocked IP details and unblock " )
                @( description, "IP numbers." )
                @( author, "Ken O. Burtch" );
  pragma license( gplv3 );
  pragma software_model( shell_script );

  with separate "lib/common.inc.sp";
  with separate "lib/blocking.inc.sp";
  with separate "lib/logins.inc.sp";
  with separate "lib/countries.inc.sp";

  pragma annotate( todo, "GeoIP should probably be moved to central server so it doesn't have to be install" );

  -- These types are not used here.  As a workaround,
  -- mark them used.  Until this is sorted out.

  pragma assumption( applied, country_data );
  pragma assumption( applied, comment_string );

  months_3   : constant natural := 60*60*24*30*3;
  weeks_1    : constant natural := 60*60*24*7;
  hours_1    : constant natural := 60*60;
  minutes_30 : constant natural := 30*60;

-- Command line options

opt_daemon  : boolean := false;   -- true of -D used

wash_log_mode : logs.log_modes := log_mode.file;

wash_lock_file : constant file_path := "lock/suspend.lck";

-- USAGE
--
-- Show the help
-----------------------------------------------------------------------------

procedure usage is
begin
  help( source_info.enclosing_entity );
end usage;


-- HANDLE COMMAND OPTIONS
--
-- Process options, if any, and return true to exit without running.
-----------------------------------------------------------------------------

function handle_command_options return boolean is
  quit : boolean := false;
  arg_pos : natural := 1;
  arg : string;
begin
  while arg_pos <= command_line.argument_count loop
    arg := command_line.argument( arg_pos );
    if arg = "-f" then
       arg_pos := @+1;
       if arg_pos > command_line.argument_count then
          put_line( standard_error, "missing argument for " & arg );
          quit;
       else
          sshd_violations_file_path := command_line.argument( arg_pos );
       end if;
    elsif arg = "-h" or arg = "--help" then
       usage;
       quit;
    elsif arg = "-v" or arg = "--verbose" then
       opt_verbose;
       wash_log_mode := log_mode.echo;
    elsif arg = "-V" or arg = "--version" then
       put_line( version );
       quit;
    elsif arg = "-D" then
       opt_daemon;
    else
       put_line( standard_error, "unknown option: " & arg );
       quit;
    end if;
    arg_pos := @+1;
  end loop;
  return quit;
end handle_command_options;


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
  --j : json_string;
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
    pragma assumption( used, ip ); -- to be investigated
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
  pragma assumption( used, search_ipinfo );

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
    pragma assumption( used, ip ); -- to be investigated
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
  pragma assumption( used, search_freegeoip );


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


  -- Health Check
  --
  -- Verify the blockers are running.  Doesn't check the tail's.

  procedure health_check is
    tmp : string;
  begin
    tmp := `ps -ef;`;
    if strings.index( tmp, "http_blocker" ) = 0 then
        logs.error( "http blocker is not running" );
    end if;
    if strings.index( tmp, "mail_blocker" ) = 0 then
        logs.error( "mail blocker is not running" );
    end if;
    if strings.index( tmp, "sshd_blocker" ) = 0 then
        logs.error( "sshd blocker is not running" );
    end if;
  end health_check;

  type country_table_rec is record
       cname : country_string;
       total : natural;
  end record;
  country_table : dynamic_hash_tables.table( json_string );

  -- Country Counts
  --
  -- Save the number of suspicious IP's by country

  procedure country_counts_report is
    f     : file_type;
    countries_file : btree_io.file( country_data );
    country : country_data;
    ctr   : country_table_rec;
    empty : boolean := false;
    j     : json_string;
    tmp   : country_string;
  begin
    btree_io.open( countries_file, string( countries_path ), countries_width, countries_width );
    if files.exists( "/root/ssds/data/country_cnt.txt" ) then
       rm /root/ssds/data/country_cnt.txt;
    end if;
    -- TODO: probably should write and switch
    create( f, out_file, "/root/ssds/data/country_cnt.txt" );
    dynamic_hash_tables.get_first( country_table, j, empty );
    while not empty loop
       records.to_record( ctr, j );
       begin
         btree_io.get( countries_file, string( ctr.cname ), country );
         tmp := country_string( country.common_name );
       exception when others =>
         -- as a precaution, if it's blank use "unknown"
         tmp := ctr.cname;
         if tmp = "" then
            tmp := "unknown";
         end if;
       end;
       put( f, ctr.total, "ZZZZZZ" );
       put_line( f, " " & tmp );
       dynamic_hash_tables.get_next( country_table, j, empty );
    end loop;
    close( f );
    btree_io.close( countries_file );
  exception when others =>
     logs.error( exceptions.exception_info );
     ? exceptions.exception_info;
     if btree_io.is_open( countries_file ) then
        btree_io.close( countries_file );
     end if;
     if is_open( f ) then
        close( f );
     end if;
  end country_counts_report;

  this_run_on : timestamp_string;
  proposed_blocked_until : timestamp_string;
  blocked_until : timestamp_string;
  needs_updating : boolean := false;
  processing_cnt : natural := 0;
  updating_cnt   : natural := 0;
  pos : natural;
  record_cnt_estimate : natural := 0;
  login_cnt : natural := 0;

  overtime : boolean := false;
  process_limit_in_secs : constant natural := minutes_30;
begin

  -- Process command options

  if handle_command_options then
     command_line.set_exit_status( 1 );
     return;
  end if;
  --opt_verbose := true; --hard-coded

  --setupWorld( "Wash Task", "log/wash.log" );
  setupWorld( "log/blocker.log", log_mode.file );

  -- do nothing if the lock file is in place.

  if files.exists( string( wash_lock_file ) ) then
     logs.warning( "exiting -- previous wash is still running" );
     shutdownWorld;
     return;
  end if;
  logs.info( "preparing to wash" );

  this_run_on := get_timestamp;

  health_check;

  startup_blocking;

  -- Ensure there was a login attempt to kickstart the ssh summary

  ssh( "-p", ssh_port, ssh_ping_user, "exit" );

  if not opt_daemon and not opt_verbose then
     put_line( "Preparing to run..." ); -- this will be overwritten

     -- Count entries.  the estimate is only used for the progress bar
     declare
       temp_cursor : btree_io.cursor( an_offender );
     begin
       btree_io.open_cursor( offender_file, temp_cursor );
       btree_io.raise_exceptions( offender_file, false );
       btree_io.get_first( offender_file, temp_cursor, key, source_ip );
       btree_io.raise_exceptions( offender_file, true );
       -- TODO: not quite right
       while btree_io.last_error( offender_file ) /= bdb.DB_NOTFOUND loop
         record_cnt_estimate := @ + 1;
         btree_io.raise_exceptions( offender_file, false );
         btree_io.get_next( offender_file, temp_cursor, key, source_ip );
         btree_io.raise_exceptions( offender_file, true );
       end loop;
       btree_io.close_cursor( offender_file, temp_cursor );
     exception when others =>
       if btree_io.is_open( offender_file ) then
         btree_io.close_cursor( offender_file, temp_cursor );
       end if;
     end;
  end if;

  btree_io.open_cursor( offender_file, abtc );
  btree_io.get_first( offender_file, abtc, key, source_ip );
  loop
     sip := source_ip.source_ip;
     if sip = "" then
        logs.warning( "source ip " & strings.to_escaped( source_ip.source_ip ) & " is invalid" );
     end if;

     if sip /= "" then
        -- logs.info( "wash is reading the country table for " & source_ip.source_ip); -- DEBUG
        declare
          ctr : country_table_rec;
          j : json_string;
        begin
          ctr.cname := source_ip.source_country;
          ctr.total := 1;
          j := dynamic_hash_tables.get( country_table, source_ip.source_country );
          if j /= "" then
             records.to_record( ctr, j );
             ctr.total := @ + 1;
          end if;
          records.to_json( j, ctr );
          dynamic_hash_tables.set( country_table, source_ip.source_country, j );
        end;

        -- show progress line

        processing_cnt := @+1;
        if not opt_daemon and not opt_verbose then
           if processing_cnt mod 250 = 0 then
              show_progress_line_no_file( this_run_on, processing_cnt, record_cnt_estimate );
           end if;
        end if;

        -- If we're running a long time, set the overtime flag.
        -- This will skip the DNS resolution step, which is time consuming,
        -- for the remaining ip addresses.  When running manually, always
        -- do DNS resolution on everything.

        if opt_daemon then
           if processing_cnt mod 100 = 0 then
              if not overtime then
                 overtime := numerics.value( string( get_timestamp ) ) > numerics.value( string( this_run_on ) ) + process_limit_in_secs;
                 if overtime then
                    logs.warning( "skipping dns and geo location starting at " & source_ip.source_ip & " - running late" );
                 end if;
              end if;
            end if;
        end if;

        -- Record validation
        --
        -- The data should normally be good.  Old records may have a different
        -- format and throw exceptions so we provide reasonable defaults here
        -- and update the old record.  We err on the side of blocking.

        --logs.info( "wash validating the record for " & source_ip.source_ip); -- DEBUG
        declare
           modified_record : boolean := false;
        begin
           if universal_typeless( source_ip.sshd_blocked_on ) = "" then
              source_ip.sshd_blocked_on := get_timestamp;
              logs.error( "for " ) @ (source_ip.source_ip)
                      @( "sshd_blocked_on timestamp was blank" );
              modified_record;
           end if;
           if universal_typeless( source_ip.sshd_offences ) = "" then
              source_ip.sshd_offences := 1;
              logs.error( "for " ) @ (source_ip.source_ip)
                      @( "sshd_offences was blank" );
              modified_record;
           end if;
           if universal_typeless( source_ip.mail_blocked_on ) = "" then
              source_ip.mail_blocked_on := get_timestamp;
              logs.error( "for " ) @ (source_ip.source_ip)
                      @( "mail_blocked_on timestamp was blank" );
              modified_record;
           end if;
           if universal_typeless( source_ip.mail_offences ) = "" then
              source_ip.mail_offences := 1;
              logs.error( "for " ) @ (source_ip.source_ip)
                      @( "mail_offences was blank" );
              modified_record;
           end if;
           if universal_typeless( source_ip.spam_blocked_on ) = "" then
              source_ip.spam_blocked_on := get_timestamp;
              logs.error( "for " ) @ (source_ip.source_ip)
                      @( "spam_blocked_on timestamp was blank" );
              modified_record;
           end if;
           if universal_typeless( source_ip.spam_offences ) = "" then
              source_ip.spam_offences := 1;
              logs.error( "for " ) @ (source_ip.source_ip)
                      @( "spam_offences was blank" );
              modified_record;
           end if;
           if universal_typeless( source_ip.http_blocked_on ) = "" then
              source_ip.http_blocked_on := get_timestamp;
              logs.error( "for " ) @ (source_ip.source_ip)
                      @( "html_blocked_on timestamp was blank" );
              modified_record;
           end if;
           if universal_typeless( source_ip.http_offences ) = "" then
              source_ip.http_offences := 1;
              logs.error( "for " ) @ (source_ip.source_ip)
                      @( "http_offences was blank" );
              modified_record;
           end if;
           if universal_typeless( source_ip.grace ) = "" then
              source_ip.grace := default_grace + 1;
              logs.error( "for " ) @ (source_ip.source_ip)
                      @( "grace was blank" );
              modified_record;
           end if;
           if universal_typeless( source_ip.updated_on ) = "" then
              -- this will get set on write
              modified_record;
           end if;
           if modified_record then
              source_ip.updated_on := get_timestamp;
              btree_io.replace( offender_file, key, source_ip );
              logs.warning( "ip " ) @ (source_ip.source_ip)
                      @( "has been updated" );
           end if;
        end;

        -- Resolve the hostname.  If we're running overtime, skip this step.

        -- logs.info( "wash resolving the hostname for " & source_ip.source_ip); -- DEBUG

        if source_ip.source_name = "" and not overtime then
           -- In Red Hat 7.7, host -W is not always honoured.
           source_host := `timeout 10 host -W 5 "$sip" ;`;
           --source_host := `host( "-W", "5", sip );`;
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
           logs.info( sip & " updated for dns and geo location" );
           needs_updating;
        end if;

        -- logs.info( "wash is updating the blocking for " & source_ip.source_ip); -- DEBUG
        blocked_until := "";
        case source_ip.sshd_blocked is
        when banned_blocked =>
             proposed_blocked_until :=
               timestamp_string(
                 strings.trim(
                   strings.image(
                     integer( numerics.value( string( source_ip.sshd_blocked_on ) ) ) +
                       weeks_1 * source_ip.sshd_offences )
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
                          hours_1 * source_ip.sshd_offences )
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

        case source_ip.mail_blocked is
        when banned_blocked =>
             proposed_blocked_until :=
               timestamp_string(
                 strings.trim(
                   strings.image(
                     integer( numerics.value( string( source_ip.mail_blocked_on ) ) ) +
                       weeks_1 * source_ip.mail_offences )
                )
             );
             if this_run_on > proposed_blocked_until then
                source_ip.mail_blocked := probation_blocked;
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
                     integer( numerics.value( string( source_ip.mail_blocked_on ) ) ) +
                       hours_1 * source_ip.mail_offences )
                )
             );
             if this_run_on > proposed_blocked_until then
                source_ip.mail_blocked := probation_blocked;
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
                       weeks_1 * source_ip.spam_offences )
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
                       hours_1 * source_ip.spam_offences )
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
                       weeks_1 * source_ip.http_offences )
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
                       hours_1 * source_ip.http_offences )
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

        -- logs.info( "wash is cleaning old records" ); -- DEBUG
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
                begin
                   btree_io.remove( offender_file, key );
                   logs.info( sip & " removed" );
                exception when others =>
                   logs.error( "failed to remove '" & key & " for " &
                       sip & "': " & exceptions.exception_info );
                end;
                logs.info( sip & " removed" );
             end if;
        else -- needs updating
           -- If some aspect has gone probationary and if the worst block
           -- has expired, then mark the IP number as probationary.
           if blocked_until /= "" then
              if this_run_on > blocked_until then
                 logs.info( sip & " on probation" );
                 unblock( sip );
              end if;
           end if;

           updating_cnt := @+1;
           needs_updating := false;
           source_ip.updated_on := this_run_on;
           begin
              btree_io.set( offender_file, key, source_ip );
           exception when others =>
              logs.error( exceptions.exception_info );
           end;
           -- TODO: do I need this next line?
           btree_io.get( offender_file, key, source_ip );
        end if;
        btree_io.raise_exceptions( offender_file, false );
        btree_io.get_next( offender_file, abtc, key, source_ip );
        exit when btree_io.last_error( offender_file ) = bdb.DB_NOTFOUND;
        btree_io.raise_exceptions( offender_file, true );
    elsif source_ip.source_ip /= "" then
        -- sip is blank or an invalid source ip was given to sip
        -- delete the invalid entry
        begin
           btree_io.remove( offender_file, key );
           logs.info( source_ip.source_ip & " removed" );
        exception when others =>
           logs.error( "failed to remove '" & key & " for " &
               source_ip.source_ip & "': " & exceptions.exception_info );
        end;
        logs.info( source_ip.source_ip & " removed" );
    end if;
  end loop;

  -- Complete progress line
  if not opt_daemon and not opt_verbose then
     tput cuu1;
     tput el;
     new_line;
  end if;

  logs.info( "wash done with ip addresses" ); -- DEBUG
  btree_io.close_cursor( offender_file, abtc );

  shutdown_blocking;

  logs.info( "Washing login accounts" );
  declare
     sshd_logins_file : btree_io.file( a_sshd_login );
     sshd_cursor : btree_io.cursor( a_sshd_login );
     login_key : string;
     login : a_sshd_login;
     last_login_username : user_string := "";
  begin
     btree_io.open( sshd_logins_file, string( sshd_logins_path ), sshd_logins_buffer_width, sshd_logins_buffer_width );
     btree_io.open_cursor( sshd_logins_file, sshd_cursor );
     btree_io.get_first( sshd_logins_file, sshd_cursor, login_key, login );
     loop
        login_cnt := @ + 1;
        -- anything that is 3 months old and only referred to once is
        -- considered random and is erased.
        begin
           proposed_blocked_until :=
              timestamp_string(
                strings.trim(
                  strings.image(
                    integer( numerics.value( string( login.updated_on ) ) ) +
                      months_3 )
                )
             );
             if this_run_on > proposed_blocked_until and
                login.count = 1 and
                login.existence /= active_existence and
                -- TODO: some of these are mislabeled
                --login.existence /= disabled_existence and
                login.kind = unknown_login_kind then
                   btree_io.remove( sshd_logins_file, login.username );
                   logs.info( login.username & " removed" );
             end if;
        exception when others =>
          logs.error( "on removing " ) @ ( login.username ) @ (" ") @ ( exceptions.exception_info );
        end;

        last_login_username := login.username; -- KLUGDE
        btree_io.get_next( sshd_logins_file, sshd_cursor, login_key, login );
        if login.username = last_login_username then
          logs.warning( "exception not raised on finding last login " );
          exit;
        end if;
     end loop;
   exception when others =>
     if btree_io.is_open( sshd_logins_file ) then
        btree_io.close_cursor( sshd_logins_file, sshd_cursor );
        btree_io.close( sshd_logins_file );
     end if;
  end;

  -- Save data for dashboard

  echo "$processing_cnt" > /root/ssds/data/blocking_cnt.txt;
  echo "$login_cnt" > /root/ssds/data/login_cnt.txt;

  country_counts_report;

  logs.ok( "Processed" ) @ ( strings.image( processing_cnt ) ) @ ( " blocking records" ) @
     ( "; Updated =" ) @ ( strings.image( updating_cnt ) ) @
     ( "; Still blocked =" ) @ ( strings.image( number_blocked ) ) @
     ( "; Login Accounts =" ) @ ( strings.image( login_cnt ) );
  shutdownWorld;
exception when others =>
  logs.error( "caught fatal exception " & exceptions.exception_info );
  if btree_io.is_open( offender_file ) then
     btree_io.close_cursor( offender_file, abtc );
     btree_io.close( offender_file );
  end if;
  shutdown_blocking;
  shutdownWorld;
end wash_blocked;

-- vim: ft=spar
