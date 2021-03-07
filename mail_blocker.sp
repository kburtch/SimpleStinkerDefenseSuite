#!/usr/local/bin/spar

with separate "config/contributors.inc.sp";
with separate "lib/world.inc.sp";
with separate "config/config.inc.sp";

procedure mail_blocker is

pragma annotate( summary, "mail_blocker [--version][-D][-f violations_file]" )
              @( description, "Process a mail log file (violations file) and block " )
              @( description, "suspicious IP numbers.  By default, the violations " )
              @( description, "file is /var/log/maillog." )
              @( param, "-D - daemon mode (run continually from sshd_daemon)" )
              @( param, "-f - path to the violations file" )
              @( param, "--version - print version and quit" )
              --@( errors, " - " )
              @( author, "Ken O. Burtch" );
pragma license( gplv3 );
pragma software_model( shell_script );

with separate "lib/common.inc.sp";
with separate "lib/blocking.inc.sp";
with separate "lib/logins.inc.sp";

-- This type is used in several places but not here.  As a workaround,
-- mark it used.  Until this is sorted out.

pragma assumption( applied, comment_string );

-- Command line options

opt_daemon  : boolean := false;   -- true of -D used

mail_log_mode : logs.log_modes := log_mode.file;

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

function handle_command_options return boolean is
  quit : boolean := false;
  arg_pos : natural := 1;
  arg : string;
begin
  while arg_pos <= command_line.argument_count loop
    arg := command_line.argument( arg_pos );
    if arg = "-h" or arg = "--help" then
       usage;
       quit;
    elsif arg = "-v" or arg = "--verbose" then
       opt_verbose;
       mail_log_mode := log_mode.echo;
    elsif arg = "-V" or arg = "--version" then
       put_line( version );
       quit;
    elsif arg = "-f" then
       arg_pos := @+1;
       if arg_pos > command_line.argument_count then
          put_line( standard_error, "missing argument for " & arg );
          quit;
       else
          smtp_violations_file_path := command_line.argument( arg_pos );
       end if;
    elsif arg = "-D" then
       opt_daemon;
       --opt_daemon := true;
    else
       put_line( standard_error, "unknown option: " & arg );
       quit;
    end if;
    arg_pos := @+1;
  end loop;
  return quit;
end handle_command_options;

-----------------------------------------------------------------------------

attack_cnt : natural; -- number of smtp attackers
spam_cnt   : natural; -- number of spammers
record_cnt : natural; -- number of records processed


-- SHOW SUMMARY
--
-- Show a summary of activity.
-----------------------------------------------------------------------------

procedure show_summary is
begin
  logs.ok( "Processed " ) @ ( strings.image( record_cnt ) ) @ ( " log records" )
     @ ( "; Attacks =" ) @ ( strings.image( attack_cnt ) )
     @ ( "; Spam =" ) @ ( strings.image( spam_cnt ) );
end show_summary;


-- RESET SUMMARY
--
-- Clear counters for the summary.
-----------------------------------------------------------------------------

procedure reset_summary is
begin
  attack_cnt := 0;
  record_cnt := 0;
  spam_cnt := 0;
end reset_summary;

-----------------------------------------------------------------------------

  f : file_type;
  this_run_on : timestamp_string;
  log_line : string;
  tmp : string;
  --tmp2 : string;
  logged_on : timestamp_string;
  raw_source_ip : raw_ip_string;
  source_ip : ip_string;
  --request : string;
  p : natural;
  is_spam : boolean;
  message : string;

  last_day   : calendar.day_number;
  this_day   : calendar.day_number;

  sshd_logins_file : btree_io.file( a_sshd_login );
  login_rec : a_sshd_login;
  is_old_login : boolean;

  outgoing_table : dynamic_hash_tables.table( integer );
  outgoing_address : string;
  outgoing_start   : natural;
  outgoing_end     : positive;
  outgoing_count   : natural;
begin
  -- Check for file existence
  if not files.exists( string( smtp_violations_file_path ) ) then
     raise configuration_error with "smtp violations file does not exist";
  end if;

  setupWorld( "log/blocker.log", mail_log_mode );

  -- Process command options

  if handle_command_options then
     command_line.set_exit_status( 1 );
     return;
  end if;

  if files.exists( string( sshd_logins_path ) ) then
     btree_io.open( sshd_logins_file, string( sshd_logins_path ), sshd_logins_buffer_width, sshd_logins_buffer_width );
  else
     btree_io.create( sshd_logins_file, string( sshd_logins_path ), sshd_logins_buffer_width, sshd_logins_buffer_width );
  end if;

  startup_blocking;

  if not opt_daemon and not opt_verbose then
     put_line( "File: " & smtp_violations_file_path );
     put_line( "Scanning records..." ); -- this will be overwritten
  end if;

  this_run_on := get_timestamp;
  last_day := calendar.day( calendar.clock );
  reset_summary;

  open( f, in_file, smtp_violations_file_path );
  while not end_of_file( f ) loop
     log_line := get_line( f );
     pragma debug( `? log_line;` );
     record_cnt := @+1;
     is_spam := false;
     source_ip := "";
     message := "";

   -- show progress line

   if not opt_daemon and not opt_verbose then
      if record_cnt mod 250 = 0 then
         show_progress_line( this_run_on, record_cnt, smtp_violations_file_path );
      end if;
   end if;

   -- Outgoing mail.  Too much email from a single user will result in an
   -- error.

   if strings.index( log_line, "from=<" ) > 0 then
      begin
         outgoing_start := strings.index( log_line, "<" )+1;
         outgoing_end   := strings.index( log_line, ">" )-1;
         outgoing_address := strings.slice( log_line, outgoing_start, outgoing_end );
         if not dynamic_hash_tables.has_element( outgoing_table, outgoing_address ) then
            dynamic_hash_tables.set( outgoing_table, outgoing_address, 1 );
         else
            outgoing_count := dynamic_hash_tables.get( outgoing_table, outgoing_address );
            if outgoing_count > alert_thresholds( outgoing_email_limit_alert ) then
               do_outgoing_email_limit_alert( outgoing_address, outgoing_count );
            else
               dynamic_hash_tables.increment( outgoing_table, outgoing_address );
            end if;
         end if;
     exception when others =>
        logs.error( exceptions.exception_info );
     end;
   end if;
     -- Dovecot POP3 Login Failures
     --
     --Jul 31 20:05:49 pegasoft dovecot: pop3-login: Login failed: Plaintext authentication disabled: user=<>, rip=151.1.221.25, lip=45.56.68.190, session=<Wm/26KVVVwCXAd0Z>
     -- TODO: grace

     if strings.index( log_line, "pop3-login: Login failed:" ) > 0 then
        raw_source_ip := raw_ip_string( strings.field( log_line, 3, '=' ) );
        raw_source_ip := raw_ip_string( strings.field( @, 1, ',' ) );
        source_ip := validate_ip( raw_source_ip );
--? "pop3 failed " & raw_source_ip & "/" & source_ip;
        logged_on := parse_timestamp( date_string( strings.slice( log_line, 1, 15 ) ) );
        attack_cnt := @+1;
        message := " has a POP3 login failure";
     end if;

     -- Dovecot POP3 Login Aborts

     if strings.index( log_line, "pop3-login: Aborted login" ) > 0 then
        raw_source_ip := raw_ip_string( strings.field( log_line, 3, '=' ) );
        raw_source_ip := raw_ip_string( strings.field( @, 1, ',' ) );
        source_ip := validate_ip( raw_source_ip );
--? "pop3 abort " & raw_source_ip & "/" & source_ip;
        logged_on := parse_timestamp( date_string( strings.slice( log_line, 1, 15 ) ) );
        attack_cnt := @+1;
        message := " has a POP3 login abort";
     end if;

     -- Dovecot IMAP Login
     --
     -- Jul 31 04:39:56 pegasoft postfix/smtpd[14149]: warning: unknown[80.82.78.85]: SASL LOGIN authentication failed: UGFzc3dvcmQ6

     if strings.index( log_line, "imap-login: Aborted" ) > 0 then
        raw_source_ip := raw_ip_string( strings.field( log_line, 3, '[' ) );
        raw_source_ip := raw_ip_string( strings.field( @, 1, ']' ) );
        source_ip := validate_ip( raw_source_ip );
--? "imap " & raw_source_ip & "/" & source_ip;
        logged_on := parse_timestamp( date_string( strings.slice( log_line, 1, 15 ) ) );
        attack_cnt := @+1;
        message := " has an IMAP login abort";
     end if;

     -- SASL PLAIN Failures
     --

     if strings.index( log_line, "SASL PLAIN authentication failed" ) > 0 then
        raw_source_ip := raw_ip_string( strings.field( log_line, 3, '[' ) );
        raw_source_ip := raw_ip_string( strings.field( @, 1, ']' ) );
        source_ip := validate_ip( raw_source_ip );
        logged_on := parse_timestamp( date_string( strings.slice( log_line, 1, 15 ) ) );
        attack_cnt := @+1;
        message := " has a SMTP-PLAIN login failure";
     end if;

     -- SASL LOGIN Failures
     --
     -- Jul 31 04:39:56 pegasoft postfix/smtpd[14149]: warning: unknown[80.82.78.85]: SASL LOGIN authentication failed: UGFzc3dvcmQ6
     -- TODO: grace

     if strings.index( log_line, "SASL LOGIN authentication failed" ) > 0 then
        raw_source_ip := raw_ip_string( strings.field( log_line, 3, '[' ) );
        raw_source_ip := raw_ip_string( strings.field( @, 1, ']' ) );
        source_ip := validate_ip( raw_source_ip );
--? "sasl " & raw_source_ip & "/" & source_ip;
        logged_on := parse_timestamp( date_string( strings.slice( log_line, 1, 15 ) ) );
        attack_cnt := @+1;
        message := " has a SMTP-LOGIN login failure";
     end if;

     -- Postfix connection dropped
     --
     -- Aug  8 19:10:10 pegasoft postfix/smtpd[8589]: lost connection after AUTH from unknown[176.44.180.230]

     if strings.index( log_line, ": lost connection after" ) > 0 then
        raw_source_ip := raw_ip_string( strings.field( log_line, 3, '[' ) );
        raw_source_ip := raw_ip_string( strings.field( @, 1, ']' ) );
        source_ip := validate_ip( raw_source_ip );
--? "lost " & raw_source_ip & "/" & source_ip;
        logged_on := parse_timestamp( date_string( strings.slice( log_line, 1, 15 ) ) );
        attack_cnt := @+1;
        message := " connection dropped";
     end if;

   -- Amavis Spam
   --
   -- Aug  3 21:38:13 pegasoft amavis[18488]: (18488-09) Blocked SPAM {DiscardedInbound,Quarantined}, [222.223.217.34]:55299 [222.223.217.34] <sburtch@ymail.com> -> <ken@pegasoft.ca>, Queue-ID: 49BB397D8, Message-ID: <1198036771.20170804033814@ymail.com>, mail_id: t7kDwBiSO3MZ, Hits: 9.649, size: 36290, 1241 ms

   if strings.index( log_line, "Blocked SPAM" ) > 0 then
      raw_source_ip := raw_ip_string( strings.field( log_line, 4, '[' ) );
      raw_source_ip := raw_ip_string( strings.field( @, 1, ']' ) );
      source_ip := validate_ip( raw_source_ip );
      logged_on := parse_timestamp( date_string( strings.slice( log_line, 1, 15 ) ) );
--? "spam " & raw_source_ip & "/" & source_ip;
      spam_cnt := @+1;
      is_spam;
      message := " sent a SPAM message";
   end if;

   -- Send mail to an unknown user
   --
   -- Treat as a spam event

   if strings.index( log_line, "User unknown in local recipient table" ) > 0 then
      raw_source_ip := raw_ip_string( strings.field( log_line, 3, '[' ) );
      raw_source_ip := raw_ip_string( strings.field( @, 1, ']' ) );
      source_ip := validate_ip( raw_source_ip );
      logged_on := parse_timestamp( date_string( strings.slice( log_line, 1, 15 ) ) );

      -- Get the username of the email

      tmp := strings.field( log_line, 2, "<" );
      tmp := strings.field( @, 1, ">" );
      tmp := strings.field( @, 1, "@" );
      login_rec.username := user_string( tmp );
      -- Virtual usernames: based on hostname or an empty string
      -- TODO: This does not work properly and should be improved.
      -- TODO: refactor out
      if string( login_rec.username ) = string( HOSTNAME ) then
         login_rec.username := " HOSTNAME";
      -- these only in sshd blocker
      -- elsif string( login_rec.username ) = hostname_base then
      --    login_rec.username := " HOSTNAME_BASE";
      -- elsif string( login_rec.username ) = hostname_stub then
      --    login_rec.username := " HOSTNAME_STUB";
      elsif login_rec.username = "" then
         login_rec.username := " BLANK_NAME";
      end if;

      if not dynamic_hash_tables.has_element( ip_whitelist, source_ip ) then
         -- Reasonable defaults for the login record
         is_old_login := false;
         if btree_io.has_element( sshd_logins_file, string( login_rec.username ) ) then
            -- Get the existing record
            -- TODO: other gets should probably use an exception handler also
            begin
               btree_io.get( sshd_logins_file, string( login_rec.username ), login_rec );
               is_old_login := true;
            exception when others =>
               logs.error( "failed to read login record: " & exceptions.exception_info );
            end;
         else
            -- Create a new one using login_rec
            if dynamic_hash_tables.has_element( known_logins, login_rec.username ) then
               login_rec.kind := existing_login;
            end if;
            login_rec.created_on := this_run_on;
         end if;
         if is_old_login then
pragma todo( team,
  "skipping old violations could be improved.  there could be multiple attacks " &
  "at the same time.  subsequent attacks in the same second are currently " &
  "skipped",
  work_measure.unknown, 0,
  work_priority.level, 'l' );
            -- Dups handled in SSHD blocker but not here
            login_rec.count := @ + 1;
         else
            init_login( login_rec, this_run_on, logged_on );
            login_rec.comment := "from spam";
            -- login_rec.count := 1;
            -- login_rec.data_type := real_data;
            -- login_rec.comment := "spam";
            -- login_rec.logged_on := logged_on;
            -- login_rec.ssh_disallowed := false;
            -- login_rec.kind := unknown_login_kind;
         end if;
         login_rec.logged_on := logged_on;
         login_rec.updated_on := this_run_on;
         btree_io.set( sshd_logins_file, string( login_rec.username ), login_rec );
         -- New logins not counted here
         is_spam;
         spam_cnt := @+1;
         message := " email to unknown user " & string( login_rec.username );
      end if; -- not whitelisted
   end if;

-- Aug  3 21:05:34 pegasoft postfix/smtpd[6517]: connect from unknown[216.16.85.53]
--     if strings.index( log_line, "postfix/smtpd" ) > 0 then
--        if strings.index( log_line, " connect from" ) > 0 then
--           raw_source_ip := raw_ip_string( strings.field( log_line, 3, '[' ) );
--           raw_source_ip := raw_ip_string( strings.field( @, 1, ']' ) );
--           source_ip := validate_ip( raw_source_ip );
--           if source_ip = "" then
--              ? log_line;
--? source_ip;
--           end if;
--           attack_cnt := @+1;
--        end if;

   -- Unfortunately, many computers may send an email without a name.
   -- This is a warning.

   if strings.index( log_line, "Name or service not known" ) > 0 then
      tmp := strings.field( log_line, 5, ':' );
      p := index_reverse( tmp, ' ' );
      if p > 0 then
         raw_source_ip := raw_ip_string( strings.slice( tmp, p+1, strings.length( tmp ) ) );
         --logged_on := parse_timestamp( date_string( strings.slice( log_line, 1, 15 ) ) );
--? "Name or service unknown: " & raw_source_ip & "/" & source_ip;
         -- attack_cnt := @+1;
      end if;
      logs.warning( raw_source_ip & " has no DNS entry" );
      --message := " has no DNS entry";
   end if;

   if source_ip /= "" then
      if opt_daemon then
         this_run_on := get_timestamp;
      end if;
      if not dynamic_hash_tables.has_element( ip_whitelist, source_ip ) then
         if is_spam then
            logs.info( source_ip )
                  @ ( " caused a SPAM threat event" );
            spam_record_and_block( source_ip, logged_on, this_run_on, true, message );
         else
            logs.info( source_ip )
                  @ ( " caused a SMTP threat event" );
            mail_record_and_block( source_ip, logged_on, this_run_on, true, message );
         end if;
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
         dynamic_hash_tables.reset( outgoing_table );
      end if;
   end if;

  end loop;

  -- Complete progress line
  if not opt_daemon and not opt_verbose then
     tput cuu1;
     tput el;
     new_line;
  end if;

  btree_io.close( sshd_logins_file );
  close( f );
  show_summary;

  -- TODO: not seeing end message in log?
  shutdown_blocking;
  shutdownWorld;

exception when others =>
  logs.error( exceptions.exception_info );
  if btree_io.is_open( sshd_logins_file ) then
     btree_io.close( sshd_logins_file );
  end if;
  if is_open( f ) then
     close( f );
  end if;
  shutdown_blocking;
  shutdownWorld;
  raise;
end mail_blocker;

-- vim: ft=spar

