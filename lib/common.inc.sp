separate;

-- This is global so it can be used throughout

opt_verbose : boolean := false;   -- true of -v used
pragma assumption( used, opt_verbose );
pragma assumption( written, opt_verbose );

--PING_CMD    : constant command := "/bin/ping";

------------------------------------------------------------------------------
-- Data categories
------------------------------------------------------------------------------

type data_types is (
  real_data,
  proxy_data,
  test_data
);
pragma todo( team,
  "ability to mark test data should be used throughout btree files",
  work_measure.story_points, 3,
  work_priority.level, 'l' );

------------------------------------------------------------------------------
-- Types of Accounts
------------------------------------------------------------------------------
-- TODO: existing, disabled should be a different type and not be here

type login_kind is (
   privileged_login,
   service_login,
   dictionary_login,
   existing_login,
   unknown_login_kind,
   role_login,
   guest_login,
   data_service_login,
   calling_card,
   disabled_login,
   email_alias_login
);


-----------------------------------------------------------------------------
-- Exported Subprograms
-----------------------------------------------------------------------------


function get_timezone return date_string;
pragma assumption( used, get_timezone );

function get_timestamp return timestamp_string;
pragma assumption( used, get_timestamp );

function parse_timestamp( s : date_string ) return timestamp_string;
pragma assumption( used, parse_timestamp );

function get_date_string( ts : timestamp_string ) return date_string;
pragma assumption( used, get_date_string );

function get_ip_number( addr : dns_string ) return ip_string;
pragma assumption( used, get_ip_number );

function get_ip_host_name( source_ip : ip_string ) return dns_string;
pragma assumption( used, get_ip_host_name );

function index_reverse( original_str : string; target : character ) return natural;
pragma assumption( used, index_reverse );

procedure fix( log_str : in out string );
pragma assumption( used, fix );

procedure show_progress_line( start_time : timestamp_string; current_cnt : natural; violations_file : file_path );
pragma assumption( used, show_progress_line );

procedure show_progress_line_no_file( start_time : timestamp_string; current_cnt : natural; estimated_cnt : natural );
pragma assumption( used, show_progress_line_no_file );

procedure setupWorld( the_log_path : string; the_log_mode : logs.log_modes );
pragma assumption( used, setupWorld );

procedure shutdownWorld;
pragma assumption( used, shutdownWorld );


------------------------------------------------------------------------------
-- Usernames
------------------------------------------------------------------------------


function get_timezone return date_string is
begin
  return `date '+%Z';`;
end get_timezone;

function get_timestamp return timestamp_string is
  -- Note: epoch time is unaffected by timezone
begin
  return `date '+%s';`;
end get_timestamp;

function parse_timestamp( s : date_string ) return timestamp_string is
  result : timestamp_string;
  dev_null : file_type;
begin
  -- As a workaround, discard errors using dev_null
  open( dev_null, out_file, "/dev/null" );
  set_error( dev_null );
  result := `date -d "$s" '+%s';`;
  set_error( standard_error );
  close( dev_null );
  return result;
end parse_timestamp;

function get_date_string( ts : timestamp_string ) return date_string is
  s : string;
begin
  s := "@" & strings.trim( string( ts ) );
  s := `date "-d" "$s";`;
  return date_string( s );
end get_date_string;

-- STATISTICS

pragma todo( team,
  "statistics not yet implemented.  requires client website first",
  work_measure.story_points, 19,
  work_priority.level, 'l' );

--type ip_statistics is record
--     daily_count_min : natural;
--     daily_count_max : natural;
--     daily_count_avg : natural;
--     year_daily_on  : calendar.year_number;
--     month_daily_on : calendar.month_number;
--     day_daily_on   : calendar.day_number;
--     seconds_daily_on : calendar.day_duration;
--end record;

------------------------------------------------------------------------------
-- IP NUMBERS
------------------------------------------------------------------------------

-- IP WHITELIST

ip_whitelist : dynamic_hash_tables.table( string );


-- GET IP NUMBER
--
-- Look up the IP number for a given DNS address.  Empty string is returned
-- if there is none.
------------------------------------------------------------------------------
pragma todo( team,
  "ping may not be best.  there is probably a better way to get an ip number",
  work_measure.story_points, 2,
  work_priority.level, 'l' );
pragma todo( team,
  "ping result shouldn't need head, cut. just use sparforte code",
  work_measure.story_points, 1,
  work_priority.level, 'l' );

-- The odds are that we will be attacked multiple times in a row by one or two
-- IP numbers.  For our purposes, cache only the most recent 8 IP's.  We could
-- use a dynamic hash table, but then we have to clear it out on a regular
-- basis...

type a_dns_cache is array(1..9) of dns_string;
type a_ip_cache is array(1..9) of ip_string;

cache_last_ip_addr_addr : a_dns_cache := ("-","-","-","-","-","-","-","-","-");
cache_last_ip_addr_ip   : a_ip_cache  := ("-","-","-","-","-","-","-","-","-");

function get_ip_number( addr : dns_string ) return ip_string is
  s : string;
begin
  -- Check to see if we already looked it up
  for i in arrays.first( cache_last_ip_addr_addr )..arrays.last( cache_last_ip_addr_addr ) loop
      if cache_last_ip_addr_addr( i ) = addr then
         return cache_last_ip_addr_ip( i );
      end if;
  end loop;
  -- Check for fake addresses
  if addr = "unknown" then
     return "";
  elsif addr = "no-reverse-dns-configured.com" then
     return "";
  end if;
  s := `/bin/dig +noall +answer A localhost | cut -f 6;`;
  -- Lookup the the ip with ping.  If found, cache it.
  -- This is broken into two lines because SparForte cannot (yet) redirect
  -- and pipe at the same time.
  --s := `ping -c 1 -W 5 "$addr" 2> /dev/null;`;
  --s := `echo "$s" | head -1 |  cut -d\( -f 2 | cut -d\) -f 1;`;
  if $? = 0 then
    arrays.shift_right( cache_last_ip_addr_addr );
    cache_last_ip_addr_addr( 1 ) := addr;
    arrays.shift_right( cache_last_ip_addr_ip );
    cache_last_ip_addr_ip( 1 ) := ip_string( s );
  else
    logs.warning( "ping unable to identify host " & addr );
  end if;
  return cache_last_ip_addr_ip( 1 );
end get_ip_number;


--  GET IP HOST NAME
--
-- Return the (first) hostname for an IP number.  An empty string is returned
-- if none was found.
-----------------------------------------------------------------------------
pragma todo( team,
  "reverse dns lookup to confirm ip address",
  work_measure.story_points, 5,
  work_priority.level, 'l' );

function get_ip_host_name( source_ip : ip_string ) return dns_string is
   tmp : string;
begin
  -- Check to see if we already looked it up recently
  for i in arrays.first( cache_last_ip_addr_ip )..arrays.last( cache_last_ip_addr_ip ) loop
      if cache_last_ip_addr_ip( i ) = source_ip then
         return cache_last_ip_addr_addr( i );
      end if;
  end loop;

  -- Look up the host name for the ip number
  tmp := `nslookup "$source_ip" | fgrep "name =" | head -1 | cut -d= -f2 ;`;
  if tmp /= "" then
     tmp := strings.delete( @, 1, 1 );
  end if;

  -- Always record the result, even if it failed, so we don't retry.
  arrays.shift_right( cache_last_ip_addr_addr );
  cache_last_ip_addr_addr( 1 ) := dns_string( tmp );
  arrays.shift_right( cache_last_ip_addr_ip );
  cache_last_ip_addr_ip( 1 ) := source_ip;

  -- If we found one, cache it.  If we found one.
  if $? = 1 then
     logs.info( source_ip & " has no host name" );
  elsif $? > 1 then
      logs.info( source_ip & " error trying to lookup hostname" );
  end if;

  return dns_string( tmp );
end get_ip_host_name;


------------------------------------------------------------------------------
-- Strings
------------------------------------------------------------------------------


-- INDEX REVERSE
--
-- Like strings.index, but start from the end of the string.
------------------------------------------------------------------------------

function index_reverse( original_str : string; target : character ) return natural is
  p : natural;
begin
  p := strings.length( original_str );
  while p > 0 loop
     exit when strings.element( original_str, p ) = target;
     p := @-1;
   end loop;
  return p;
end index_reverse;


-- FIX
--
-- Remove extra spaces from a string.  When two adjacent spaces are found,
-- remove one until only single spaces remain in the string..
------------------------------------------------------------------------------

procedure fix( log_str : in out string ) is
  p : natural;
begin
  loop
    p := strings.index( log_str, "  " );
  exit when p = 0;
    log_str := strings.delete( log_str, p, p );
  end loop;
end fix;


------------------------------------------------------------------------------
-- UI
------------------------------------------------------------------------------

-- SHOW PROGRESS LINE
--
-- Show the status when processing a file with sshd violations
------------------------------------------------------------------------------
pragma todo( team,
  "possibly move ui subprograms to a separate file",
  work_measure.story_points, 1,
  work_priority.level, 'l' );

show_progress_line_size_cache : natural := 0;
show_progress_line_last_modified : calendar.time;

procedure show_progress_line( start_time : timestamp_string; current_cnt : natural; violations_file : file_path ) is
  now       : timestamp_string;
  elapsed   : universal_numeric;
  estimated_cnt : natural;
  last_modified : calendar.time;
  minutes_left : universal_typeless := " ??";
  percent   : universal_typeless := " ??";
begin
  -- Move up one line to the start of the progress line

  tput cuu1;

  -- Get the time and number of lines in the file
  -- (This assumes the file can change size during the run, but we don't want
  -- to spend a lot of time counting lines so we cache it.  Every 1500 lines
  -- check to see if the file was modified.  If it was, update the line count.)

  now := get_timestamp;
  if show_progress_line_size_cache = 0 then
     show_progress_line_last_modified := files.last_modified( string( violations_file ) );
     show_progress_line_size_cache := natural( numerics.value(  `wc -l < "$violations_file";` )
 );
  elsif current_cnt mod 1500 = 0 then
     last_modified := files.last_modified( string( violations_file ) );
     if last_modified /= show_progress_line_last_modified then
        show_progress_line_last_modified := last_modified;
        show_progress_line_size_cache := natural( numerics.value(  `wc -l < "$violations_file";` ) );
    end if;
  end if;

  estimated_cnt := show_progress_line_size_cache;

  -- Compute the percentage complete and time remaining
  -- Delay the status until we've at least done 1000 records, as initial
  -- stats won't be meaningful.  Use floor to favour 99% over 100%.

  elapsed := numerics.value( string( now ) ) - numerics.value( string( start_time ) );
  if current_cnt >= 1000 then
     minutes_left := numerics.unbiased_rounding( elapsed * float( estimated_cnt ) / float( current_cnt ) );
     minutes_left := numerics.floor( (@ - elapsed )/60 );
  end if;
  if estimated_cnt > 0 then
     percent := 100 * current_cnt / estimated_cnt;
  end if;

  -- Display the line

  put( current_cnt )
   @ ( " of" )
   @ ( estimated_cnt )
   @ ( " records (" )
   @ ( percent )
   @ ( "%, est." )
   @ ( minutes_left )
   @ ( " min remaining)" );
  tput el;
  new_line;
exception when others =>
  put_line( "error calculating the progress line" );
end show_progress_line;

-- Same but no file to monitor

procedure show_progress_line_no_file( start_time : timestamp_string; current_cnt : natural; estimated_cnt : natural ) is
  now       : timestamp_string;
  elapsed   : universal_numeric;
  --last_modified : calendar.time;
  minutes_left : universal_typeless := " ??";
  percent   : universal_typeless := " ??";
begin
  -- Move up one line to the start of the progress line

  tput cuu1;

  now := get_timestamp;

  -- Compute the percentage complete and time remaining
  -- Delay the status until we've at least done 1000 records, as initial
  -- stats won't be meaningful.  Use floor to favour 99% over 100%.

  elapsed := numerics.value( string( now ) ) - numerics.value( string( start_time ) );
  if current_cnt >= 1000 then
     minutes_left := numerics.unbiased_rounding( elapsed * float( estimated_cnt ) / float( current_cnt ) );
     minutes_left := numerics.floor( (@ - elapsed )/60 );
  end if;
  if estimated_cnt > 0 then
     percent := 100 * current_cnt / estimated_cnt;
  end if;

  -- Display the line

  put( current_cnt )
   @ ( " of" )
   @ ( estimated_cnt )
   @ ( " records (" )
   @ ( percent )
   @ ( "%, est." )
   @ ( minutes_left )
   @ ( " min remaining)" );
  tput el;
  new_line;
exception when others =>
  put_line( "error calculating the progress line" );
end show_progress_line_no_file;

------------------------------------------------------------------------------
-- Housekeeping
------------------------------------------------------------------------------

configuration_error : exception;

-- SETUP WORLD
--
-- Startup the common features such as the log file.
------------------------------------------------------------------------------

procedure setupWorld( the_log_path : string;
  the_log_mode : logs.log_modes ) is
  min_version : constant string := "2.1";
  ip : ip_string;
  desc : string;
begin
  logs.open( the_log_path, the_log_mode, 75 );

  -- probably should be improved...
  if HOSTNAME = "" then
     HOSTNAME := `hostname;`;
  end if;

  -- Check configuration

  if System.System_Version < min_version then
    raise configuration_error with "SparForte " & min_version &
       " is required.  This is " & System.System_Version & ".";
  end if;

  -- operating_system := `uname -s;`;

pragma todo( team,
  "whitelist should be in a configuration file not hard-coded",
  work_measure.story_points, 2,
  work_priority.level, 'l' );
pragma todo( team,
  "whitelist should be broken into separate lists for peers and clients",
  work_measure.story_points, 1,
  work_priority.level, 'l' );

  for i in arrays.first(ip_whitelist_config)..arrays.last(ip_whitelist_config) loop
      ip := strings.csv_field( ip_whitelist_config(i), 1 );
      desc :=strings.csv_field( ip_whitelist_config(i), 2 );
      dynamic_hash_tables.set( ip_whitelist, ip, desc );
      logs.info( "whitelisted " ) @ (ip) @( " as " ) @ (desc);
  end loop;
end setupWorld;

-- SHUTDOWN WORLD
--
------------------------------------------------------------------------------

procedure shutdownWorld is
begin
   if logs.is_open then
      logs.close;
   end if;
end shutdownWorld;

-- vim: ft=spar
