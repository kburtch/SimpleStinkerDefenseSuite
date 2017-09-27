separate;

-- This is global so it can be used throughout

opt_verbose : boolean := false;   -- true of -v used

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
-- Usernames
------------------------------------------------------------------------------

-- VALIDATE_USER
--
-- Return an empty string if not a valid username, otherwise return the name.
------------------------------------------------------------------------------

function validate_user( user : raw_user_string ) return user_string is
begin
  if not strings.is_graphic( user ) then
     return "";
  end if;
  -- Spaces are considered graphic...but aren't allowed in a username
  if strings.index( user, " " ) > 0 then
     return "";
  end if;
  -- Implementation dependent.  Linux allows up to 32 characters.
  if strings.length( user ) > 32 then
     return "";
  end if;
  return user_string( user );
end validate_user;


------------------------------------------------------------------------------
-- IP Numbers
------------------------------------------------------------------------------

-- VALIDATE_IP
--
-- Return an empty string if the string is not a IPv4 IP number, otherwise
-- return the number.
------------------------------------------------------------------------------

function validate_ip( ip : raw_ip_string ) return ip_string is
  p : positive;

  function expect_byte return boolean is
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
    return byte /= "";
  end expect_byte;

  function expect_period return boolean is
    period : boolean;
  begin
    if p > strings.length( ip ) then
       return false;
    end if;
    period := strings.element( string( ip ), p ) = '.';
    p := @+1;
    return period;
  end expect_period;

begin
  if ip = "" then
     return "";
  end if;
  p := 1;
  if not expect_byte then
     return "";
  end if;
  if not expect_period then
     return "";
  end if;
  if not expect_byte then
     return "";
  end if;
  if not expect_period then
     return "";
  end if;
  if not expect_byte then
     return "";
  end if;
  if not expect_period then
     return "";
  end if;
  if not expect_byte then
     return "";
  end if;
  if p <= strings.length( ip ) then
     return "";
  end if;
  return ip_string( ip );
end validate_ip;

-- TIME AND TIME ZONES
--
-- The calendar package doesn't support timezones.
-- The date command is affected by TZ:
--TZ : string;
--pragma export( shell, TZ );

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
begin
  return `date -d "$s" '+%s';`;
end parse_timestamp;

-- LOGGING

log_file : file_type;
log_path : string;
log_string : string;
program_name : string;


-- LOG INFO
--
-- Log an info-level message to the log.
-----------------------------------------------------------------------------

procedure log_info( message : universal_string ) is
  context : constant chains.context := chains.chain_context;
begin
  case context is
  when chains.context_first =>
     log_string := `date;` & ":";
     log_string := @ & "INFO:";
     log_string := @ & message &  ":";
  when chains.context_middle =>
     log_string := @ & message;
  when chains.context_last =>
     log_string := @ & message;
     create( log_file, append_file, log_path );
     put_line( log_file, log_string );
     if opt_verbose then
        put_line( log_string );
     end if;
     close( log_file );
  when chains.not_in_chain =>
     log_string := `date;` & ":";
     log_string := @ & "INFO:";
     log_string := @ & source_info.file &  ":";
     log_string := @ & message;
     create( log_file, append_file, log_path );
     put_line( log_file, log_string );
     if opt_verbose then
        put_line( log_string );
     end if;
     close( log_file );
  when others =>
     put_line( standard_error, "unexpect chain context" );
  end case;
end log_info;


-- LOG WARNING
--
-- Log an warning-level message to the log.
-----------------------------------------------------------------------------

procedure log_warning( message : universal_string ) is
  context : constant chains.context := chains.chain_context;
begin
  case context is
  when chains.context_first =>
     log_string := `date;` & ":";
     log_string := @ & "WARNING:";
     log_string := @ & message &  ":";
  when chains.context_middle =>
     log_string := @ & message;
  when chains.context_last =>
     log_string := @ & message;
     create( log_file, append_file, log_path );
     put_line( log_file, log_string );
     if opt_verbose then
        put_line( log_string );
     end if;
     close( log_file );
  when chains.not_in_chain =>
     log_string := `date;` & ":";
     log_string := @ & "WARNING:";
     log_string := @ & source_info.file &  ":";
     log_string := @ & message;
     create( log_file, append_file, log_path );
     put_line( log_file, log_string );
     if opt_verbose then
        put_line( log_string );
     end if;
     close( log_file );
  when others =>
     put_line( standard_error, "unexpect chain context" );
  end case;
end log_warning;


-- LOG ERROR
--
-- Log an error-level message to the log.
-----------------------------------------------------------------------------

procedure log_error( message : universal_string ) is
  context : constant chains.context := chains.chain_context;
begin
  case context is
  when chains.context_first =>
     log_string := `date;` & ":";
     log_string := @ & "ERROR:";
     log_string := @ & message &  ":";
  when chains.context_middle =>
     log_string := @ & message;
  when chains.context_last =>
     log_string := @ & message;
     create( log_file, append_file, log_path );
     put_line( log_file, log_string );
     if opt_verbose then
        put_line( log_string );
     end if;
     close( log_file );
  when chains.not_in_chain =>
     log_string := `date;` & ":";
     log_string := @ & "ERROR:";
     log_string := @ & source_info.file &  ":";
     log_string := @ & message;
     create( log_file, append_file, log_path );
     put_line( log_file, log_string );
     if opt_verbose then
        put_line( log_string );
     end if;
     close( log_file );
  when others =>
     put_line( standard_error, "unexpect chain context" );
  end case;
end log_error;


-- LOG START
--
-- Open the log file for logging.
-----------------------------------------------------------------------------

procedure log_start is
begin
  log_info( "Start " & program_name & " run" );
end log_start;


-- LOG END
--
-- Close the log file.
-----------------------------------------------------------------------------

procedure log_end is
begin
  log_info( "End " & program_name & " run" );
end log_end;

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

ip_whitelist : dynamic_hash_tables.table( ip_string );


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
    log_warning( source_info.file ) @ ( "ping unable to identify host " & addr );
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
     log_info( source_info.file ) @ ( source_ip & " has no host name" );
  elsif $? > 1 then
      log_info( source_info.file ) @ ( source_ip & " error trying to lookup hostname" );
  end if;

  return dns_string( tmp );
end get_ip_host_name;

-- Reverse DNS example
-- /bin/dig +noall +answer -x 127.0.0.1 # localhost | cut -f 6
-- 1.0.0.127.in-addr.arpa.	10800	IN	PTR	localhost.

------------------------------------------------------------------------------
-- Strings
------------------------------------------------------------------------------

-- INDEX REVERSE
--
-- Like strings.index, but start from the end of the string.
------------------------------------------------------------------------------

function index_reverse( str : string; target : character ) return natural is
  p : natural;
begin
  p := strings.length( str );
  while p > 0 loop
     exit when strings.element( str, p ) = target;
     p := @-1;
   end loop;
  return p;
end index_reverse;

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
        show_progress_line_size_cache := natural( numerics.value(  `wc -l < "$violations_file"; ` ) );
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

------------------------------------------------------------------------------
-- Housekeeping
------------------------------------------------------------------------------

configuration_error : exception;

-- SETUP WORLD
--
-- Startup the common features such as the log file.
------------------------------------------------------------------------------

procedure setupWorld( the_program_name : string; the_log_path : string ) is
  min_version : constant string := "2.1";
begin

  program_name := the_program_name;
  log_path := the_log_path;
  log_start;

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

  dynamic_hash_tables.set( ip_whitelist, "127.0.0.1", "localhost" );
  dynamic_hash_tables.set( ip_whitelist, "45.56.68.190", "lntxap01" );
  dynamic_hash_tables.set( ip_whitelist, "198.58.125.175", "armitage" );
  dynamic_hash_tables.set( ip_whitelist, "209.159.182.101", "home" );
end setupWorld;

-- SHUTDOWN WORLD
--
------------------------------------------------------------------------------

procedure shutdownWorld is
begin
   log_end;
end shutdownWorld;

-- vim: ft=spar
