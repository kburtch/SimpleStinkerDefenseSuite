separate;

-- CONFIGURATION

type operating_modes is (
  monitor_mode,
  honeypot_mode,
  local_blocking_mode,
  shared_blocking_mode
);

mode : operating_modes := monitor_mode;

-- STANDARD DATA TYPES
--
-- TODO: raw types (vs. validated types)

type user_string is new string;
type ip_string is new string;
type port_string is new string;
type dns_string is new string;
type comment_string is new string;
type date_string is new string;
type timestamp_string is new string;
type country_string is new string;

type firewall_kinds is (
  iptables_firewall,
  iptables_old_firewall,
  initd_iptables_firewall,
  firewalld_firewall,
  suse_firewall
);
firewall_kind : firewall_kinds := iptables_firewall;

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
     close( log_file );
  when chains.not_in_chain =>
     log_string := `date;` & ":";
     log_string := @ & "INFO:";
     log_string := @ & source_info.file &  ":";
     log_string := @ & message;
     create( log_file, append_file, log_path );
     put_line( log_file, log_string );
     close( log_file );
  when others =>
     put_line( standard_error, "unexpect chain context" );
  end case;
end log_info;


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

-- SUSPICIOUS LOGINS

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
end record;

sshd_logins_path : constant string := "data/sshd_logins.btree";
sshd_logins_buffer_width : constant positive := 512;

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
end record;
-- TODO: offenses is american, offences is Canadian

blocked_ip_path : constant string := "data/blocked_ip.btree";
blocked_ip_buffer_width : constant positive := 512;

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

   if firewall_kind = iptables_firewall then
     if mode /= monitor_mode and mode /= honeypot_mode then
        ipset -q list blocklist >/dev/null 2>/dev/null ;
        if $? /= 0 then
           ipset create blocklist iphash ;
           iptables -A INPUT "--match-set" blocklist src -j DROP ;
           iptables -A INPUT "--match-set" blocklist dst -j REJECT ;
        end if;
     end if;
   end if;

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

