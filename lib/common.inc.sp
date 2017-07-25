separate;

-- This is global so it can be used throughout

opt_verbose : boolean := false;   -- true of -v used

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
-- TODO: monitor should output to standard output/error

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
-- TODO: monitor should output to standard output/error

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
-- TODO: monitor should output to standard output/error

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

-- COUNTRIES

type country_data is record
   iso3166 : string;
   common_name : string;
   suffix : string;
end record;

countries_path : constant string := "data/countries.btree";
countries_width : constant positive := 128;

-- SUSPICIOUS LOGINS

type data_types is (
  real_data,
  proxy_data,
  test_data
);

type login_kind is (
   privileged_login,
   service_login,
   dictionary_login,
   existing_login,
   unknown_login_kind
-- calling card
);

type a_sshd_login is record
     username   : user_string;
     count      : natural;
     ssh_disallowed : boolean;
     kind       : login_kind;
     comment    : comment_string;
     created_on : timestamp_string;
     logged_on  : timestamp_string;
     updated_on : timestamp_string;
     data_type       : data_types;
end record;

sshd_logins_path : constant string := "data/sshd_logins.btree";
sshd_logins_buffer_width : constant positive := 2048;

-- ALREADY BLOCKING

type blocking_status is (
  unblocked_blocked,
  probation_blocked,
  short_blocked,
  banned_blocked,
  blacklisted_blocked
);

type a_blocked_ip is record
     source_ip       : ip_string;
     source_name     : dns_string;
     source_country  : country_string;
     location        : string;
     sshd_blocked    : blocking_status;
     sshd_blocked_on : timestamp_string;
     sshd_offenses   : natural;
     smtp_blocked    : blocking_status;
     smtp_blocked_on : timestamp_string;
     smtp_offenses   : natural;
     http_blocked    : blocking_status;
     http_blocked_on : timestamp_string;
     http_offenses   : natural;
     created_on      : timestamp_string;
     logged_on       : timestamp_string;
     updated_on      : timestamp_string;
     data_type       : data_types;
end record;
-- TODO: offenses is american, offences is Canadian

blocked_ip_path : constant string := "data/blocked_ip.btree";
blocked_ip_buffer_width : constant positive := 2048;

-- STATISTICS

type ip_statistics is record
     daily_count_min : natural;
     daily_count_max : natural;
     daily_count_avg : natural;
     year_daily_on  : calendar.year_number;
     month_daily_on : calendar.month_number;
     day_daily_on   : calendar.day_number;
     seconds_daily_on : calendar.day_duration;
end record;

-- KNOWN LOGINS

known_logins : dynamic_hash_tables.table( user_string );

procedure check_known_logins is
-- TODO: doesn't handle active directory type services...only local
  f : file_type;
  s : string;
  user : user_string;
begin
  open( f, in_file, "/etc/passwd" );
  while not end_of_file( f ) loop
     s := get_line( f );
     user := user_string( strings.field( s, 1, ":" ) );
     dynamic_hash_tables.set( known_logins, user, user );
  end loop;
  close( f );
end check_known_logins;

-- IP WHITELIST

ip_whitelist : dynamic_hash_tables.table( ip_string );

-- IP BLACKLIST

procedure setupWorld( the_program_name : string; the_log_path : string ) is
begin
   program_name := the_program_name;
   log_path := the_log_path;
   log_start;

   -- Setup an ip set to hold all banned ip numbers
   -- To delete the whole set, use ipset destroy
   -- (Delete the iptables rules first)
   -- TODO: use command types

   --if firewall_kind = iptables_firewall then
   --  if mode /= monitor_mode and mode /= honeypot_mode then
   --     ipset -q list blocklist >/dev/null 2>/dev/null ;
   --     if $? /= 0 then
   --        ipset create blocklist iphash ;
   --        iptables -A INPUT "--match-set" blocklist src -j DROP ;
   --        iptables -A INPUT "--match-set" blocklist dst -j REJECT ;
   --     end if;
   --  end if;
   --end if;

   -- TODO: should read from file

  dynamic_hash_tables.set( ip_whitelist, "127.0.0.1", "localhost" );
  dynamic_hash_tables.set( ip_whitelist, "45.56.68.190", "lntxap01" );
  dynamic_hash_tables.set( ip_whitelist, "198.58.125.175", "armitage" );

  check_known_logins;
end setupWorld;

procedure shutdownWorld is
begin
   log_end;
end shutdownWorld;

-- vim: ft=spar

