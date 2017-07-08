#!/usr/local/bin/spar

procedure sshd_blocker is
  pragma annotate( summary, "sshd_blocker" )
                @( description, "Search login violations and block " )
                @( description, "offending IP numbers." )
                @( author, "Ken O. Burtch" );
  pragma license( gplv3 );

with separate "world.inc.sp";
with separate "blocking.inc.sp";

-- TODO: check against /etc/passwd
--   report warnings
--   load into dht for use here

type shell_import_string is new string;

HOSTNAME : constant shell_import_string := "";
pragma import( shell, HOSTNAME );

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

--username : user_string;
--ip : ip_string;

blocked_ip_file : btree_io.file( a_blocked_ip );
sshd_logins_file : btree_io.file( a_sshd_login );

-- TODO: this should be integrated with blocking.inc.sp:block function
procedure block_if_not( source_ip : ip_string; logged_on : timestamp_string ) is
  ab : a_blocked_ip;
begin
  if not btree_io.has_element( blocked_ip_file, string( source_ip ) ) then
     ab.source_ip       := source_ip;
     ab.source_name     := "";
     ab.source_country  := "";
     ab.location        := "";
     ab.sshd_blocked    := short_blocked;
     ab.sshd_blocked_on := this_run_on;
     ab.sshd_offenses   := 1;
     ab.smtp_blocked    := unblocked_blocked;
     ab.smtp_blocked_on := this_run_on;
     ab.smtp_offenses   := 0;
     ab.http_blocked    := unblocked_blocked;
     ab.http_blocked_on := this_run_on;
     ab.http_offenses   := 0;
     ab.created_on      := this_run_on;
     ab.logged_on       := logged_on;
     ab.updated_on      := this_run_on;
     btree_io.set( blocked_ip_file, string( source_ip ), ab );
     block( source_ip );
  else
     btree_io.get( blocked_ip_file, string( source_ip ), ab );
     -- TODO: not a guarantee since could be overlap
     if ab.logged_on < logged_on then
        if ab.sshd_blocked <= probation_blocked then
   --log_info( source_info.file ) @ ( "re-blocking ip " & source_ip ); -- DEBUG
           ab.sshd_blocked    := short_blocked;
           ab.sshd_blocked_on := this_run_on;
           ab.sshd_offenses   := @+1;
           ab.logged_on       := logged_on;
           ab.updated_on      := this_run_on;
           -- TODO: banned escallation
           btree_io.set( blocked_ip_file, string( source_ip ), ab );
           if ab.http_blocked > probation_blocked then
              log_info( source_info.file ) @ ( "already HTML blocked " & source_ip );
           elsif ab.smtp_blocked > probation_blocked then
              log_info( source_info.file ) @ ( "already SMTP blocked " & source_ip );
           else
              block( source_ip );
           end if;
        --else -- DEBUG
        --   log_info( source_info.file ) @ ( "already blocked " & source_ip ); -- DEBUG
        end if;
     --else
        --log_info( source_info.file ) @ ( "skipping dup IP " & source_ip ); -- DEBUG
     end if;
  end if;
end block_if_not;

--lock_file_path : constant string := "sshd_blocker.lck"; -- DEBUG: no := storage error

sshd_violations_file_path : string := "/var/log/secure";

source_ip : ip_string;
processing_cnt : natural;
new_cnt : natural;
dup_cnt : natural;
updated_cnt : natural;

hostname_base : string;
hostname_stub : string;

opt_daemon : boolean := false;

-- USAGE
--
-- Show the help
-----------------------------------------------------------------------------

procedure usage is
begin
  put_line( "sshd_blocker [-D][-f violations_file]" );
  new_line;
  put_line( "Process a sshd log file (violations file) and block" );
  put_line( "suspicious IP numbers" );
  new_line;
  put_line( " -f - path to the violations file" );
  put_line( " -D - daemon mode (run continually from sshd_daemon)" );
  new_line;
  put_line( "By default, violations file is /var/log/secure" );
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

begin

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

if mode in monitor_mode..honeypot_mode then
   if files.exists( sshd_logins_path ) then
      btree_io.open( sshd_logins_file, sshd_logins_path, sshd_logins_buffer_width, sshd_logins_buffer_width );
   else
      btree_io.create( sshd_logins_file, sshd_logins_path, sshd_logins_buffer_width, sshd_logins_buffer_width );
   end if;
end if;

if files.exists( blocked_ip_path ) then
   btree_io.open( blocked_ip_file, blocked_ip_path, blocked_ip_buffer_width, blocked_ip_buffer_width );
else
   btree_io.create( blocked_ip_file, blocked_ip_path, blocked_ip_buffer_width, blocked_ip_buffer_width );
end if;

-- this is the sshd log

open( f, in_file, sshd_violations_file_path );

-- setup variables

processing_cnt := 0;
new_cnt := 0;
dup_cnt := 0;
updated_cnt := 0;
this_run_on := get_timestamp;
r.created_on := this_run_on;
create_login_hostname_variants( hostname_base, hostname_stub );

process := false;
while not end_of_file( f ) loop
   processing_cnt := @+1;

   -- we are parsing the entries in the human-readable sshd log

   s_original := get_line( f );
   p := strings.index( s_original, " sshd[" );
   if p > 0 then
      s := s_original;
      -- TODO: failed password is only relevant to honeypot mode.
      -- should be brocessing the other line to block.
      -- "Invalid user" (with capital "I") entires appear for key-pair to
      -- a non-existing account
      --found := remove_token( s, "Invalid user" );
      if found then
         found := remove_token( s, " from " );
         fix( s );
         r.username := user_string( strings.field( s, 6, ' ' ) );
         source_ip := ip_string( strings.field( s, 7, ' ' ) );
         process;
      end if;
      -- "not listed in" entries are key-pair logins to an existing account
      -- which failed
      found := remove_token( s, "not allowed because not listed in AllowUsers" );
      if found then
? s;
         found := remove_token( s, " from " );
         found := remove_token( s, "User " );
         r.username := user_string( strings.field( s, 6, ' ' ) );
         source_ip := ip_string( strings.field( s, 7, ' ' ) );
? r.username;
         process;
      end if;
      -- "Failed password" entries appear with SSH PasswordAuthentication
      found := remove_token( s, "Failed password" );
      if found then
         -- if waiting on a named pipe, refresh current time.
         -- remove noise
         found := remove_token( s, " for " );
         found := remove_token( s, " from " );
         found := remove_token( s, " port  " );
         found := remove_token( s, "invalid user" );
         if found then
            r.ssh_disallowed := true;
         end if;
         fix( s );
         r.username := user_string( strings.field( s, 6, ' ' ) );
         source_ip := ip_string( strings.field( s, 7, ' ' ) );
         process;
       end if;
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
         r.comment := "";
         if string( r.username ) = string( HOSTNAME ) then
            r.username := " HOSTNAME";
         elsif string( r.username ) = hostname_base then
            r.username := " HOSTNAME_BASE";
         elsif string( r.username ) = hostname_stub then
            r.username := " HOSTNAME_STUB";
         end if;
? "processing: " & r.username;
         records.to_json( j, r );
         if mode in monitor_mode..honeypot_mode then
            if not dynamic_hash_tables.has_element( ip_whitelist, source_ip ) then
               if btree_io.has_element( sshd_logins_file, string( r.username ) ) then
                  btree_io.get( sshd_logins_file, string( r.username ), old_r );
                  -- TODO: not a guarantee: there could be multiple attacks at the
                  -- same time.
                  if old_r.logged_on > r.logged_on then
                     dup_cnt := @+1;
                  else
                     updated_cnt := @+1;
                     old_r.count := @ + 1;
                     old_r.logged_on := r.logged_on;
                     old_r.updated_on := this_run_on;
--                     btree_io.set( sshd_logins_file, string( r.username ), old_r );
                  end if;
               else
                  new_cnt := @+1;
                  r.updated_on := this_run_on;
--                  btree_io.set( sshd_logins_file, string( r.username ), r );
               end if;
            end if;
         end if;
null;--         block_if_not( source_ip, r.logged_on );
      end if;
   end if;
end loop;

close( f );
btree_io.close( blocked_ip_file );
if mode in monitor_mode..honeypot_mode then
   btree_io.close( sshd_logins_file );
end if;

if mode in monitor_mode..honeypot_mode then
   log_info( source_info.source_location ) @
      ( "Processed" ) @ ( strings.image( processing_cnt ) ) @ ( " log records: " ) @
      ( "New usernames: " ) @ ( strings.image( new_cnt ) ) @
      ( "; Old records: " ) @ ( strings.image( dup_cnt ) ) @
      ( "; Old usernames: " ) @ ( strings.image( updated_cnt ) );
else
   log_info( source_info.source_location ) @
      ( "Processed" ) @ ( strings.image( processing_cnt ) ) @ ( " log records" );
end if;

--lock_files.unlock_file( lock_file_path );
shutdownWorld;

exception when others =>
  close( f );
  btree_io.close( blocked_ip_file );
  if mode in monitor_mode..honeypot_mode then
     btree_io.close( sshd_logins_file );
  end if;
  --lock_files.unlock_file( lock_file_path );
  shutdownWorld;
  raise;
end sshd_blocker;

-- vim: ft=spar

