#!/usr/local/bin/spar

with separate "config/contributors.inc.sp";
with separate "lib/world.inc.sp";
with separate "config/config.inc.sp";

procedure sshd_blocker is

pragma annotate( summary, "sshd_blocker [--version][-D][-f violations_file]" )
              @( description, "Process a sshd log file (violations file) and block " )
              @( description, "suspicious IP numbers.  By default, the violations " )
              @( description, "file is /var/log/secure." )
              @( param, "-D - daemon mode (run continually from sshd_daemon)" )
              @( param, "-f - path to the violations file" )
              @( param, "--version - print version and quit" )
              --@( errors, " - " )
              @( author, "Ken O. Burtch" );
pragma license( gplv3 );
pragma software_model( shell_script );

with separate "lib/logging.inc.sp";
with separate "lib/common.inc.sp";
with separate "lib/blocking.inc.sp";
with separate "lib/logins.inc.sp";

procedure create_login_hostname_variants( base : in out string; stub : in out string ) is
  p : natural;
begin
  base := "";
  stub := "";
  p := strings.index( HOSTNAME, '.' );
  if p > 1 then
     base := strings.delete( HOSTNAME, p, strings.length( HOSTNAME ) );
     p := strings.index( HOSTNAME, "-" );
     if p > 1 then
        stub := strings.delete( HOSTNAME, p, strings.length( HOSTNAME ) );
     end if;
  end if;
end create_login_hostname_variants;

function remove_token( str : in out string; token : string ) return boolean is
  p : natural;
begin
  p := strings.index( str, token );
  if p > 0 then
     str := strings.delete( @, p, p + strings.length( token )-1 );
     str := strings.insert( @, p, " " );
  end if;
  return p > 0;
end remove_token;

procedure fix( str : in out string ) is
  p : natural;
begin
  loop
    p := strings.index( str, "  " );
  exit when p = 0;
    str := strings.delete( str, p, p );
  end loop;
end fix;

j : limited json_string;
f : file_type;
s : string;
s_original : string;
p : natural;
r : a_sshd_login;
old_r : a_sshd_login;
found : boolean;
process : boolean;
this_run_on : timestamp_string;

sshd_logins_file : btree_io.file( a_sshd_login );

--lock_file_path : constant string := "sshd_blocker.lck"; -- DEBUG: no := storage error

raw_source_ip  : raw_ip_string;  -- an IPv4 number, unverified
source_ip      : ip_string;      -- an IPv4 number
raw_username   : raw_user_string; -- a login name, unverified
processing_cnt : natural;        -- number of sshd record processed
new_cnt        : natural;        -- new login names seen
dup_cnt        : natural;        -- number of records already seen
updated_cnt    : natural;        -- number of old login names seen
message        : string;         -- log message
last_day       : calendar.day_number;
this_day       : calendar.day_number;

hostname_base : string;          -- x-y of x-y.cloud.com
hostname_stub : string;          -- x   of x-y.cloud.com

-- Command line options

opt_daemon  : boolean := false;   -- true of -D used


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
       echo_logging;
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


-- GET RAW USERNAME AND IP NUMBER
--
-- The username can be blank or contain spaces.  We have to handle
-- these cases.
--
-- For a name with spaces, loop and add pieces until only the IP
-- number is left.  The IP number is right after.
-- offset is 2 or 4, depending on "PORT xxx" is on the line
-----------------------------------------------------------------------------

procedure get_raw_username_and_ip_number( offset : positive) is
   p : natural := 6;
begin
   --log_info( source_info.source_location ) @ ( s); -- DEBUG
   raw_username := "";
   loop
      raw_username := @ & raw_user_string( strings.field( s, p, ' ' ) );
   exit when strings.field( s, p+offset, ' ' ) = "";
      raw_username := @ & ' ';
      p := @ + 1;
   end loop;
   raw_source_ip := raw_ip_string( strings.field( s, p+1, ' ' ) );
   -- No IP number?  Then the username was blank and position 6 has
   -- the IP number.
   if raw_source_ip = "" then
      raw_username := "";
      raw_source_ip := raw_ip_string( strings.field( s, 6, ' ' ) );
   end if;
end get_raw_username_and_ip_number;

-- SHOW SUMMARY
--
-- Show a summary of activity.
-----------------------------------------------------------------------------

procedure show_summary is
begin
   log_ok( source_info.source_location ) @
      ( "Processed" ) @ ( strings.image( processing_cnt ) ) @ ( " log records: " ) @
      ( "New usernames: " ) @ ( strings.image( new_cnt ) ) @
      ( "; Old records: " ) @ ( strings.image( dup_cnt ) ) @
      ( "; Old usernames: " ) @ ( strings.image( updated_cnt ) );
end show_summary;

-- RESET SUMMARY
--
-- Clear counters for the summary.
-----------------------------------------------------------------------------

procedure reset_summary is
begin
  processing_cnt := 0;
  new_cnt := 0;
  dup_cnt := 0;
  updated_cnt := 0;
end reset_summary;

begin
  -- Check for file existence
  if not files.exists( string( sshd_violations_file_path ) ) then
     raise configuration_error with "sshd violations file does not exist";
  end if;

setupWorld( "SSHD blocker", "log/blocker.log" );

-- Process command options

if handle_command_options then
   command_line.set_exit_status( 1 );
   return;
end if;

--lock_files.lock_file( "sshd_blocker.lck" );

-- A login may look like the hostname.  Calculate variations on the hostname
-- for this.

-- we are storing the results here

-- Logins are only tracked in honeypot mode

--if mode in monitor_mode..honeypot_mode then
   if files.exists( string( sshd_logins_path ) ) then
      btree_io.open( sshd_logins_file, string( sshd_logins_path ), sshd_logins_buffer_width, sshd_logins_buffer_width );
   else
      btree_io.create( sshd_logins_file, string( sshd_logins_path ), sshd_logins_buffer_width, sshd_logins_buffer_width );
   end if;
--end if;

check_known_logins;
startup_blocking;

if not opt_daemon and not opt_verbose then
   put_line( "File: " & sshd_violations_file_path );
   put_line( "Scanning records..." ); -- this will be overwritten
end if;

-- this is the sshd log

open( f, in_file, sshd_violations_file_path );

-- setup variables

reset_summary;
this_run_on := get_timestamp;
last_day := calendar.day( calendar.clock );
r.created_on := this_run_on;
create_login_hostname_variants( hostname_base, hostname_stub );

process := false;
while not end_of_file( f ) loop
   processing_cnt := @+1;
   source_ip := "";
   message := "";

   -- show progress line

   if not opt_daemon and not opt_verbose then
      if processing_cnt mod 250 = 0 then
         show_progress_line( this_run_on, processing_cnt, sshd_violations_file_path );
      end if;
   end if;

   -- we are parsing the entries in the human-readable sshd log

   s_original := get_line( f );
   pragma debug( `? s_original;` );
   p := strings.index( s_original, " sshd[" );
   if p > 0 then
      s := s_original;
      -- Entry: "Invalid user" (with capital "I") entires appear for key-pair to
      -- a non-existing account
      -- e.g. Invalid user admin from 185.165.29.41
pragma todo( team,
  "clean up main sshd logic and refactor with more subprograms",
  work_measure.story_points, 2,
  work_priority.level, 'l' );
      found := remove_token( s, "Invalid user" );
      if found then
         found := remove_token( s, " from " );
         r.logged_on := parse_timestamp( date_string( strings.slice( s, 1, 15 ) ) );
         fix( s );
         --log_info( source_info.source_location ) @ ("raw string is '" & strings.to_escaped( s )& "'" ); -- DEBUG
         get_raw_username_and_ip_number( 4 ); -- was 2
         r.username := validate_user( raw_username );
         if validate_ip( raw_ip_string( raw_username ) ) /= "" then
            log_warning( source_info.source_location ) @ ("username is an ip number '" & strings.to_escaped( raw_username ) & "' in " & s_original );
         else
            if raw_username /= "" and r.username = "" then
               log_warning( source_info.source_location ) @ ("saw invalid username '" & strings.to_escaped( raw_username ) & "'" );
            end if;
         end if;
         r.ssh_disallowed := true;
         source_ip := validate_ip( raw_source_ip );
         if source_ip /= "" then
            message := " no such user account";
            process;
         else
            log_warning( source_info.source_location ) @ ( "skipping invalid ip '" & strings.to_escaped( raw_source_ip ) & "'" );
         end if;
      end if;
      -- Entry: "not listed in" entries are key-pair logins to an existing account
      -- which failed.  Note that this will be a dup with "Failed password" if SSH
      -- PasswordAuthentication is on.
      -- e.g. User root from 181.26.141.145 not allowed because not listed in AllowUsers
      found := remove_token( s, "not allowed because not listed in AllowUsers" );
      if found then
         found := remove_token( s, " from " );
         found := remove_token( s, "User " );
         fix( s );
         -- Edge-case: If line reads "User User", the username will have been
         -- removed by remove_token.  Same with "User from".  Blank username
         -- is also possible.
         declare
            source_addr : dns_string;
         begin
            if strings.index( s_original, "User User " ) > 0 then
               r.username := "User";
               source_addr :=dns_string( strings.field( s, 6, ' ' ) );
               source_ip := get_ip_number( source_addr );
            elsif strings.index( s_original, "User from " ) > 0 then
               r.username := "from";
               source_addr :=dns_string( strings.field( s, 6, ' ' ) );
               source_ip := get_ip_number( source_addr );
            else
               raw_username := raw_user_string( strings.field( s, 6, ' ' ) );
               r.username := validate_user( raw_username );
               if validate_ip( raw_ip_string( raw_username ) ) /= "" then
                  log_warning( source_info.source_location ) @ ("username is an ip number '" & strings.to_escaped( raw_username ) & "' in " & s_original );
               else
                  if raw_username /= "" and r.username = "" then
                     log_warning( source_info.source_location ) @ ("saw invalid username '" & strings.to_escaped( raw_username ) & "'" );
                  end if;
               end if;
               source_addr  := dns_string( strings.field( s, 7, ' ' ) );
               if source_addr = "" then
                  r.username := "";
                  source_addr  := dns_string( strings.field( s, 6, ' ' ) );
                  source_ip := get_ip_number( source_addr );
               else
                  source_ip := get_ip_number( source_addr );
               end if;
            end if;
            r.ssh_disallowed := true;
            if source_ip /= "" then
               message := " remote login disallowed";
               process;
            else
               log_warning( source_info.source_location ) @ ( "ip not found for address '" & source_addr & "'" );
            end if;
         end;
      end if;
      -- Entry: "Failed password" entries appear with SSH PasswordAuthentication
      -- e.g. Failed password for invalid user root from 180.128.21.46 port 52988 ssh2
      found := remove_token( s, "Failed password" );
      if found then
         -- "user port from...port" is a possibility.  Unfortunately, sshd doesn't
         -- clearly deliniate the username.
         if index_reverse( s, " user port from " ) = 0 then
            found := remove_token( s, " port  " );
         end if;
         -- if waiting on a named pipe, refresh current time.
         -- remove noise
         found := remove_token( s, " for " );
         -- "user from from" is a possibility, but it is safe to leave one as
         -- we delete one "from" and leave the other to be treated as a
         -- username
         found := remove_token( s, " from " );
         found := remove_token( s, "invalid user" );
         r.ssh_disallowed := found;
         fix( s );
         get_raw_username_and_ip_number( 5 );
         r.username := validate_user( raw_username );
         if validate_ip( raw_ip_string( raw_username ) ) /= "" then
            log_warning( source_info.source_location ) @ ("username is an ip number '" & strings.to_escaped( raw_username ) & "' in " & s_original );
         else
            if raw_username /= "" and r.username = "" then
               log_warning( source_info.source_location ) @ ("saw invalid username '" & strings.to_escaped( raw_username ) & "'" );
            end if;
         end if;
         source_ip := validate_ip( raw_source_ip );
         if source_ip /= "" then
            message := " login failed";
            process;
         else
            log_warning( source_info.source_location ) @ ("skipping invalid ip '" & strings.to_escaped( raw_source_ip ) & "'" );
         end if;
       end if;
       -- If we detected a failed login, process it
       if process then
         process := false;
         r.count := 1;
         if opt_daemon then
            this_run_on := get_timestamp;
         end if;
         if dynamic_hash_tables.has_element( known_logins, r.username ) then
            r.kind := existing_login;
         else
            r.kind := unknown_login_kind;
         end if;
         r.data_type := real_data;
         r.comment := "";
         -- Virtual usernames: based on hostname or an empty string
         if string( r.username ) = string( HOSTNAME ) then
            r.username := " HOSTNAME";
         elsif string( r.username ) = hostname_base then
            r.username := " HOSTNAME_BASE";
         elsif string( r.username ) = hostname_stub then
            r.username := " HOSTNAME_STUB";
         elsif r.username = "" then
            r.username := " BLANK_NAME";
         end if;
         records.to_json( j, r );
         --if mode in monitor_mode..honeypot_mode then
            if not dynamic_hash_tables.has_element( ip_whitelist, source_ip ) then
               if btree_io.has_element( sshd_logins_file, string( r.username ) ) then
                  btree_io.get( sshd_logins_file, string( r.username ), old_r );
pragma todo( team,
  "skipping old violations could be improved.  there could be multiple attacks " &
  "at the same time.  subsequent attacks in the same second are currently " &
  "skipped",
  work_measure.unknown, 0,
  work_priority.level, 'l' );
                  if old_r.logged_on > r.logged_on then
                     dup_cnt := @+1;
                  else
                     updated_cnt := @+1;
                     old_r.count := @ + 1;
                     old_r.logged_on := r.logged_on;
                     old_r.updated_on := this_run_on;
                     btree_io.set( sshd_logins_file, string( r.username ), old_r );
                  end if;
               else
                  new_cnt := @+1;
                  r.updated_on := this_run_on;
                  btree_io.set( sshd_logins_file, string( r.username ), r );
               end if;
               sshd_record_and_block( source_ip, r.logged_on, this_run_on, opt_daemon, message);
            end if; -- whitelisted
         --end if;
      end if;
   end if;

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

-- Close files
close( f );
shutdown_blocking;
--if mode in monitor_mode..honeypot_mode then
   btree_io.close( sshd_logins_file );
--end if;

-- Record summary
--if mode in monitor_mode..honeypot_mode then
   show_summary;
--else
--   log_info( source_info.source_location ) @
--      ( "Processed" ) @ ( strings.image( processing_cnt ) ) @ ( " log records" );
--end if;

--lock_files.unlock_file( lock_file_path );
shutdownWorld;

exception when others =>
  -- Log the exception and close files
  log_error( source_info.source_location ) @ ( exceptions.exception_info );
  if is_open( f ) then
     close( f );
  end if;
  shutdown_blocking;
--  if mode in monitor_mode..honeypot_mode then
     if btree_io.is_open( sshd_logins_file ) then
        btree_io.close( sshd_logins_file );
     end if;
--  end if;
  --lock_files.unlock_file( lock_file_path );
  shutdownWorld;
  raise;
end sshd_blocker;

-- vim: ft=spar

