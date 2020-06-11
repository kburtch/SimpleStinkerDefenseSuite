#!/usr/local/bin/spar

with separate "config/contributors.inc.sp";
with separate "lib/world.inc.sp";
with separate "config/config.inc.sp";

procedure http_blocker is

pragma annotate( summary, "http_blocker [--version][-D][-f violations_file]" )
              @( description, "Process a http log file (violations file) and block " )
              @( description, "suspicious IP numbers.  By default, the violations " )
              @( description, "file is /var/log/httpd/access_log." )
              @( param, "-D - daemon mode (run continually from sshd_daemon)" )
              @( param, "-f - path to the violations file" )
              @( param, "--version - print version and quit" )
              --@( errors, " - " )
              @( author, "Ken O. Burtch" );
pragma license( gplv3 );
pragma software_model( shell_script );

with separate "lib/common.inc.sp";
with separate "lib/blocking.inc.sp";
with separate "lib/key_codes.inc.sp";
with separate "lib/urls.inc.sp";

-- Command line options

opt_daemon  : boolean := false;   -- true of -D used

-----------------------------------------------------------------------------
-- Web requests
-----------------------------------------------------------------------------

  candidate_key_codes : dynamic_hash_tables.table( key_codes );


-- COUNT WEB REQUEST CODES
--
-- For debugging
-----------------------------------------------------------------------------

--procedure count_web_request_codes is
--   key_code : key_codes;
--   eof : boolean;
--   cnt : natural := 0;
--   -- s   : string;
--begin
--    dynamic_hash_tables.get_first( candidate_key_codes, key_code, eof );
--    while not eof loop
--       cnt := @+1;
--       dynamic_hash_tables.get_next( candidate_key_codes, key_code, eof );
--    end loop;
--    log_info( source_info.source_location ) @ ( "there are" &
--       strings.image( cnt ) & " request key codes" );
--    cnt := 0;
--    --btree_io.get_first( vectors_file, , s, eof );
--    --while not eof loop
--    --   cnt := @+1;
--    --   dynamic_hash_tables.get_next( attack_vectors, s, eof );
--    --end loop;
--    --log_info( source_info.source_location ) @ ( "there are" &
--    --   strings.image( cnt ) & " attack vector key codes" );
--end count_web_request_codes;


-- PREPARE WEB REQUEST
--
-- Parse the web requests, identifying all the key codes in the request.
-- Mark these in the candidate key codes hash table.  In this way, only
-- attack vectors starting with key codes in the web request will be tested.
-----------------------------------------------------------------------------

  procedure prepare_web_request( request : string ) is
     key_code : key_codes;
     --key_code_1 : key_codes;
     --key_code_2 : key_codes;
     key_code_string : string;
  begin
    dynamic_hash_tables.reset( candidate_key_codes );
    for i in 1..strings.length( request )-2 loop
      --key_code := to_basic_key_code( strings.element( request, i ) );
      key_code := to_key_code( strings.slice( request, i, strings.length( request ) ) );
      key_code_string := strings.image( key_code );
      dynamic_hash_tables.add( candidate_key_codes, key_code_string, key_code );
    end loop;
    -- count_web_request_codes;
  end prepare_web_request;


-- SUSPICIOUS WEB REQUEST
--
-- Process all the key codes identifed by prepare_web_request, searching
-- the web request for the presence of attack vector substrings.
-----------------------------------------------------------------------------

  --function suspicious_web_request( request : string; source_ip : ip_string; message : out string ) return boolean is
  procedure suspicious_web_request( request : string; message : out string; result : out boolean ) is
    key_code : key_codes;
    eof : boolean;
    key_code_string : string;
    vectors : an_attack_vector;
    vector : string;
    v : natural;
    found : boolean := false;
  begin
    dynamic_hash_tables.get_first( candidate_key_codes, key_code, eof );
    while not eof and not found loop
         --if key_code /= 30 then
         if key_code /= 300 then
            key_code_string := strings.image( key_code );
            if btree_io.has_element( vectors_file, key_code_string ) then
               btree_io.get( vectors_file, key_code_string, vectors);
               v := 1;
               loop
                  vector := strings.field( vectors.vector, v, ASCII.LF );
                  exit when vector = "";
                  if strings.index( request, vector ) > 0 then
                     -- The IP is added to the message elsewhere...not sure
                     -- where but it isn't needed here.
                     -- message := string( source_ip ) &
                     message := " made a suspicious web request '" &
                        strings.to_escaped( request ) &
                        "' with '" &
                        strings.to_escaped( vector ) & "'";
                     found;
                     exit;
                  end if;
                  v := @+1;
               end loop;
            end if;
         end if;
         dynamic_hash_tables.get_next( candidate_key_codes, key_code, eof );
    end loop;
    result := found;
  end suspicious_web_request;


--  IS SEARCH ENGINE
--
-- True if name seems to be a major search engine.  The name comes from
-- nslookup and includes trailing period.
-----------------------------------------------------------------------------

--function _search_engine( dns_host: dns_string; source_ip : ip_string ) return boolean is
procedure check_for_search_engine( dns_host: dns_string; source_ip : ip_string; result : out boolean ) is
  found : boolean := false;
  host  : string;
begin
  host := string( dns_host ) & "~";
  -- Archive.org
  found := strings.index( host, ".archive.org.~" ) > 0;
  if not found then
     -- China
     found := strings.index( host, "crawl.baidu.com.~" ) > 0;
  end if;
  if not found then
     -- DuckDuckGo
     found := strings.index( host, "duckduckgo.com.~" ) > 0;
  end if;
  if not found then
     -- France
     found := strings.index( host, "exabot.com.~" ) > 0;
  end if;
  if not found then
     -- Google
     found := strings.index( host, "googlebot.com.~" ) > 0;
  end if;
  if not found then
     -- Japan / Korea
     found := strings.index( host, "naver.jp.~" ) > 0;
  end if;
  if not found then
     -- Microsoft
     found := strings.index( host, "search.msn.com.~" ) > 0;
  end if;
  if not found then
     -- SemRush.com
     found := strings.index( host, ".semrush.com.~" ) > 0;
  end if;
  if not found then
     -- Czek Republic search engine
     found := strings.index( host, ".seznam.cz.~" ) > 0;
  end if;
  if not found then
     found := strings.index( host, "softlayer.com.~" ) > 0;
  end if;
  if not found then
     -- Slurp URL's hard to distinguish from basic yahoo.com
     found := strings.index( host, ".yahoo.com.~" ) > 0;
  end if;
  if not found then
     -- Slurp URL's hard to distinguish from basic yahoo.com
     found := strings.index( host, ".yahoo.net.~" ) > 0;
  end if;
  if not found then
      -- Russia
     found := strings.index( host, "yandex.com.~" ) > 0;
  end if;
  -- coccocbot is vietnam
  if found then
     logs.warning( source_ip ) @ ( " is whitelisted as a seach engine" );
  end if;
  result := found;
end check_for_search_engine;


-----------------------------------------------------------------------------
-- Housekeeping
-----------------------------------------------------------------------------


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
-----------------------------------------------------------------------------

http_violations_file_path : file_path;
http_log_mode : logs.log_modes := log_mode.file;

--function handle_command_options return boolean is
procedure handle_command_options( quit : out boolean ) is
  arg_pos : natural := 1;
  arg : string;
begin
  quit := false;
  while arg_pos <= command_line.argument_count loop
    arg := command_line.argument( arg_pos );
    if arg = "-h" or arg = "--help" then
       usage;
       quit;
    elsif arg = "-f" then
       arg_pos := @+1;
       if arg_pos > command_line.argument_count then
          put_line( standard_error, "missing argument for " & arg );
          quit;
       else
          http_violations_file_path := command_line.argument( arg_pos );
       end if;
    elsif arg = "-v" or arg = "--verbose" then
       opt_verbose;
       http_log_mode := log_mode.echo;
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
end handle_command_options;
-----------------------------------------------------------------------------

record_cnt : natural;
attack_cnt : natural;
last_day   : calendar.day_number;
this_day   : calendar.day_number;


-- SHOW SUMMARY
--
-- Show a summary of activity.
-----------------------------------------------------------------------------

procedure show_summary is
begin
  logs.ok ( "Processed" ) @ ( strings.image( record_cnt ) ) @ ( " log records" )
     @ ( "; Attacks =" ) @ ( strings.image( attack_cnt ) );
end show_summary;


-- RESET SUMMARY
--
-- Clear counters for the summary.
-----------------------------------------------------------------------------

procedure reset_summary is
begin
  record_cnt := 0;
  attack_cnt := 0;
end reset_summary;


-----------------------------------------------------------------------------

  f : file_type;
  this_run_on : timestamp_string;
  log_line : string;
  tmp : string;
  tmp2 : string;
  http_status : http_status_string;
  logged_on : timestamp_string;
  raw_source_ip : raw_ip_string;
  source_ip : ip_string;
  host : dns_string;
  request : string;
  message : string;
  is_suspicious : boolean := false;
  is_search_engine : boolean := false;
  must_quit : boolean := false;
begin
  -- Default
  http_violations_file_path := http_violations_file_paths( 1 );

  -- Check for file existence
  if not files.exists( string( vectors_path ) ) then
     raise configuration_error with "vectors file does not exist";
  end if;
  if not files.exists( string( http_violations_file_path ) ) then
     raise configuration_error with "http violations file does not exist";
  end if;

  -- Process command options

  handle_command_options( must_quit );
  if must_quit  then
     command_line.set_exit_status( 1 );
     return;
  end if;

  setupWorld( "log/blocker.log", http_log_mode );

  startup_blocking;

  if not opt_daemon and not opt_verbose then
     put_line( "File: " & http_violations_file_path );
     put_line( "Scanning records..." ); -- this will be overwritten
  end if;

  btree_io.open( vectors_file, string( vectors_path ), vectors_width, vectors_width );

  this_run_on := get_timestamp;
  last_day := calendar.day( calendar.clock );
  reset_summary;

  open( f, in_file, http_violations_file_path );
  while not end_of_file( f ) loop
     log_line := get_line( f );
     pragma debug( `? log_line;` );
     record_cnt := @+1;
     source_ip := "";

     -- show progress line

     if not opt_daemon and not opt_verbose then
        if record_cnt mod 250 = 0 then
           show_progress_line( this_run_on, record_cnt, http_violations_file_path );
        end if;
     end if;

     -- A typical log line:
     --162.250.145.207 - - [26/Feb/2019:10:05:36 -0500] "GET /resources/boblap/toc.html HTTP/1.1" 200 7649 "http://www.pegasoft.ca/resources/boblap/book.html" "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0"

     -- for all intents and purposes, the apache log line is a space
     -- delimited CSV, which also handles the double-quotes.
     --
     -- There are also cases where the fallback code below does not work
     -- because of code with quotes in the identification string.

     http_status := http_status_string( strings.csv_field( log_line, 7, ' ' ) );

     -- However, csv_field may fail on malformed log lines such as requests
     -- that include embedded malicious source code with quotes.  Apache
     -- does not escape these quotes.  As a workaround, search for the field
     -- starting at the end of the log line.
     --
     -- TODO: this should probably be a function.
     -- TODO: probably some improvement here

     if strings.length( http_status ) /= 3 then
        declare
          p       : natural := strings.length( log_line );
          last_p  : natural := p;
          f       : natural := 4;
          inQuote : boolean := false;
          ch      : character;
        begin
           -- searching from the end of the web server log line
           while p > 0 loop
              ch := strings.element( log_line, p );
              if ch = '"' then
                 if p = strings.length( log_line ) then
                    inQuote := not inQuote;
                 else
                    -- kludge: quote is only legitimate if there's an adjacent space
                    ch := strings.element( log_line, p+1 );
                    if ch = ' ' then
                       inQuote := not inQuote;
                    end if;
                    if p > 1 then
                       ch := strings.element( log_line, p-1 );
                       -- kludge: quote is only legitimate if there's an adjacent space
                       if ch = ' ' then
                          inQuote := not inQuote;
                       end if;
                    end if;
                 end if;
              elsif ch = ' ' and not inQuote then
                 if p /= strings.length( log_line ) then --and ch = '"' then
                    f := @-1;
                    exit when f = 0;
                    last_p := p-1;
                 end if;
              end if;
              p := @-1;
           end loop;
           -- p stops on a space.  if we didn't exhaust the string
           -- and the status field (4th from right) was found.
           if p > 0 and f = 0 then
              http_status := strings.slice( log_line, p+1, last_p);
           end if;
        end;
     end if;

     -- It is still possible for both of these operations above to fail
     -- to get the http status.  In that case, it's assigned code 999
     -- and treated as a failure.
     --
     -- When using the tail command to examine the logs, perhaps due to
     -- volume, tail can choke and will only return the end of a log line.

     if http_status = "" then
        http_status := "999";
        logs.warning( "http_status is blank on log line " ) @ (log_line);
     elsif http_status = "-" then
        http_status := "999";
     elsif strings.length( http_status ) /= 3 then
        http_status := "999";
        logs.warning( "http_status is not length 3 on log line " ) @ (log_line);
     elsif not strings.is_digit( http_status ) then
        http_status := "999";
        logs.warning( "http_status is not numeric on log line " ) @ (log_line);
     end if;

     -- ignoring 999 because tail command may have corrupted the line
     if strings.index( " 400 401 403 404 405 413 414 500 ", string( http_status ) ) > 0 then
        request := strings.field( log_line, 2, '"' ) & strings.field( log_line, 6, '"' );
        -- Check the IP number.  If it's whitelisted, ignore the rest of the processing
        -- because it is somewhat expensive.
        raw_source_ip := raw_ip_string( strings.field( log_line, 1, ' ' ) );
        source_ip := validate_ip( raw_source_ip );
        if source_ip = "" then
           logs.error( " - unable to validate IP '" )
                  @ ( raw_source_ip )
                  @ ( "' on log line " )
                  @ ( log_line );
        else
           if not dynamic_hash_tables.has_element( ip_whitelist, source_ip ) then
              prepare_web_request( request );
              suspicious_web_request( request, message, is_suspicious );
              if is_suspicious then
                 host := get_ip_host_name( source_ip );
                 check_for_search_engine( host, source_ip, is_search_engine );
                 if not is_search_engine then
                    -- remove colon in middle of date/time
                    -- convert month to number
                    -- e.g. 28/Jan/2018:03:18:50 -0500
                    begin
                       tmp := strings.field( log_line, 2, '[' );
                       if strings.length( tmp ) < 20 then
                          logged_on := "";
                          logs.error( " - unable to extract date '" )
                                 @ ( tmp )
                                 @ ( "' on log line " )
                                 @ ( log_line );
                       else
                          if strings.index( tmp, ' ' ) > 0 then
                             tmp := strings.delete( tmp,
                                 strings.index( tmp, ' ' ),
                                 strings.length( tmp ) );
                          end if;
                          tmp := strings.replace_slice( tmp, 12, 12, ' ' );
                          if strings.index( tmp, "Jan" ) > 0 then
                            tmp := strings.replace_slice( tmp, 4, 6, "01" );
                          elsif strings.index( tmp, "Feb" ) > 0 then
                            tmp := strings.replace_slice( tmp, 4, 6, "02" );
                          elsif strings.index( tmp, "Mar" ) > 0 then
                            tmp := strings.replace_slice( tmp, 4, 6, "03" );
                          elsif strings.index( tmp, "Apr" ) > 0 then
                            tmp := strings.replace_slice( tmp, 4, 6, "04" );
                          elsif strings.index( tmp, "May" ) > 0 then
                            tmp := strings.replace_slice( tmp, 4, 6, "05" );
                          elsif strings.index( tmp, "Jun" ) > 0 then
                            tmp := strings.replace_slice( tmp, 4, 6, "06" );
                          elsif strings.index( tmp, "Jul" ) > 0 then
                            tmp := strings.replace_slice( tmp, 4, 6, "07" );
                          elsif strings.index( tmp, "Aug" ) > 0 then
                            tmp := strings.replace_slice( tmp, 4, 6, "08" );
                          elsif strings.index( tmp, "Sep" ) > 0 then
                            tmp := strings.replace_slice( tmp, 4, 6, "09" );
                          elsif strings.index( tmp, "Oct" ) > 0 then
                            tmp := strings.replace_slice( tmp, 4, 6, "10" );
                          elsif strings.index( tmp, "Nov" ) > 0 then
                            tmp := strings.replace_slice( tmp, 4, 6, "11" );
                          elsif strings.index( tmp, "Dec" ) > 0 then
                            tmp := strings.replace_slice( tmp, 4, 6, "12" );
                          end if;
                          -- swap day and month
                          tmp2 := strings.head( tmp, 3 );
                          tmp := strings.delete( tmp, 1, 3 );
                          tmp := strings.insert( tmp, 4, tmp2 );
                          logged_on := parse_timestamp( date_string( tmp ) );
                       end if;
                       if logged_on = "" then
                          logs.error( " - unable to convert date " )
                                 @ ( tmp )
                                 @ ( " on log line " )
                                 @ ( log_line );
                          logged_on := this_run_on;
                       end if;
                    exception when others =>
                        logs.error( exceptions.exception_info )
                               @ ( " - unable to convert date " )
                               @ ( tmp )
                               @ ( " on log line " )
                               @ ( log_line );
                        logged_on := this_run_on;
                    end;
                    if source_ip /= "" then
                       logs.info( source_ip )
                              @ ( " caused a HTTP threat event" );
                       http_record_and_block( source_ip, logged_on, this_run_on, true, message );
                    else
                       logs.warning( "skipping invalid ip '" & strings.to_escaped( raw_source_ip ) & "'" )
                                @ ( " on the log line " )
                                @ ( log_line );
                    end if;
                    attack_cnt := @+1;
                 end if; -- not search engine
              end if; -- not suspicious
           end if; -- not whitelisted
        end if; -- not valid ip
     end if; -- not 4xx status

   -- periodically check for a new day and display the summary of activity
   -- on a new day

   if opt_daemon then
      this_day := calendar.day( calendar.clock );
      if this_day /= last_day then
         last_day := this_day;
         show_summary;
         reset_summary;
      end if;
   end if;
  end loop;

  -- Complete progress line
  if not opt_daemon and not opt_verbose then
     tput cuu1;
     tput el;
     new_line;
  end if;

  show_summary;

  close( f );
  btree_io.close( vectors_file );
  shutdown_blocking;
  shutdownWorld;

exception when others =>
  if logs.is_open then
     logs.error( exceptions.exception_info );
   else
      put_line( standard_error, exceptions.exception_info );
   end if;
  if btree_io.is_open( vectors_file ) then
     btree_io.close( vectors_file );
  end if;
  if is_open( f ) then
     close( f );
  end if;
  shutdown_blocking;
  shutdownWorld;
  -- DEBUG
  --raise;
  ? exceptions.exception_info;
end http_blocker;

-- vim: ft=spar

