separate;

-- LOGGING

-- Global Settings
--
-- Set echo logging to true to show log also to standard output
-----------------------------------------------------------------------------

--  LOG MODES
--
-- stderr_log - write entries to standard error
-- file_log   - write to specified file
-- echo_log   - write to file and standard error

type log_modes is ( stderr_log, file_log, echo_log );

-- Private Settings
-----------------------------------------------------------------------------

type a_log_level is new natural;

log_path : string;                                        -- path to log file
log_lock_file_path : string := "logger.lck";             -- path to lock file
log_mode : log_modes := stderr_log;                        -- type of logging

log_width : constant integer := 75;             -- minimum width before entry

log_program_name : string;                        -- name of invoking program

log_string_header : string;                          -- leading part of entry
log_string_message : string;                                 -- body of entry
log_level : a_log_level;                               -- entry nesting level
log_indent_required : natural;                  -- true if indent not applied
log_started_message : boolean := true;                   -- true if new entry

log_last_message : string := "";             -- last entry body for dup check
log_dup_count : natural := 0;                        -- number of dup entries


-----------------------------------------------------------------------------
-- Utilties
-----------------------------------------------------------------------------


--  LOG LEVEL START
--
-- Started a nested log level.  Increases the indent of log messages.
-----------------------------------------------------------------------------

function log_level_start return a_log_level is
  old_level : a_log_level := log_level;
begin
  log_level := @+1;
  return old_level;
end log_level_start;


--  LOG LEVEL END
--
-- Complete a nested log level.  Resets the indent of log messages.
-----------------------------------------------------------------------------

procedure log_level_end( old_level : a_log_level ) is begin
  log_level := old_level;
end log_level_end;


--  LOG INDENT MESSAGE
--
-- Add the indent field to a log message.
-----------------------------------------------------------------------------

procedure log_indent_message( msg : in out string; clear_indent : boolean ) is
begin
  while strings.length( log_string_header & msg ) < log_width loop
     msg := @ & ' ';
  end loop;
  if log_indent_required > 0 then
     msg := @ & (log_indent_required * ' ');
     if clear_indent then
        log_indent_required := 0;
     end if;
  end if;
  msg := @  &  ":";
end log_indent_message;


--  LOG CLEAN MESSAGE
--
-- Escape special characters (including colon, used to denote log fields).
-----------------------------------------------------------------------------

procedure log_clean_message( message : in out universal_string ) is
  p : natural;
begin
  -- Escape colons
  loop
     p := strings.index( message, ':' );
  exit when p = 0;
     message := strings.delete( @, p, p );
     message := strings.insert( @, p, "[# 58]" );
  end loop;
  -- Escape control characters
  message := strings.to_escaped( @ );
  return message;
end log_clean_message;

-----------------------------------------------------------------------------
-- Core Loggers
-----------------------------------------------------------------------------


--  LOG FIRST PART
--
-- Build the first part of the log message: date, program and location.
-----------------------------------------------------------------------------

procedure log_first_part( m : universal_string; level_tag : string ) is
begin
  log_string_header := `date;` & ":";
  log_string_message := strings.trim( strings.image( os.pid ) ) & ":"; --strings.image($$) & ":";
  log_string_message := @ & source_info.enclosing_entity & ":";
  log_string_message := @ & level_tag & ":";
  log_string_message := @ & m & ":";
  log_indent_required := log_level * 2;
  log_started_message := false;
end log_first_part;


--  LOG MIDDLE PART
--
-- Build the middle part of the log message.  Indent and show the first
-- or next part of the user's message.
-----------------------------------------------------------------------------

procedure log_middle_part( m : universal_string ) is
begin
  if not log_started_message then
     log_indent_message( log_string_message, true );
     log_started_message;
  end if;
  log_string_message := @ & m;
end log_middle_part;


--  LOG LAST PART
--
-- Build the last part of the log message.  Indent (if needed) and show the
-- last of the user's message.
-----------------------------------------------------------------------------

procedure log_last_part( m : universal_string ) is
  log_file : file_type;                                        -- log file fd
  repeat_message : string;                                -- entry about dups
begin
  if not log_started_message then
     log_indent_message( log_string_message, false );
     log_started_message;
  end if;
  log_string_message := @ & m;
  if log_string_message = log_last_message then
     log_dup_count := @ + 1;
  else
     -- Open the log file
     -- The lock file prevents two processes from logging on the same line
     lock_files.lock_file( log_lock_file_path );
     create( log_file, append_file, log_path );

     -- Handle duplicate messages
     -- If there was one dup, just show it.
     -- if there were multiple dups, show the count
     if log_dup_count = 1 then
        if log_mode = file_log or log_mode = echo_log then
           put_line( log_file, log_string_header & log_last_message );
        end if;
        if log_mode = stderr_log or log_mode = echo_log then
           put_line( standard_error, log_string_header & log_last_message );
        end if;
     elsif log_dup_count > 0 then
        repeat_message := strings.trim( strings.image( os.pid ) ) & ":";
        repeat_message := @ & source_info.enclosing_entity & ":";
        repeat_message := @ & "INFO:" & source_info.file & ": 0:";
        log_indent_message( repeat_message, false );
        repeat_message := @ &  "... repeated" & strings.image( log_dup_count ) & " times";
        if log_mode = file_log or log_mode = echo_log then
           put_line( log_file, log_string_header & repeat_message );
        end if;
        if log_mode = stderr_log or log_mode = echo_log then
           put_line( standard_error, log_string_header & repeat_message );
        end if;
        log_dup_count := 0;
     end if;

     -- Log the message
     if log_mode = file_log or log_mode = echo_log then
        put_line( log_file, log_string_header & log_string_message );
     end if;
     if log_mode = stderr_log or log_mode = echo_log then
        put_line( standard_error, log_string_header & log_string_message );
     end if;
     log_last_message := log_string_message;

      -- Release the lock
     close( log_file );
     lock_files.unlock_file( log_lock_file_path );
  end if;
  log_indent_required := 0;
  log_string_message := "";
end log_last_part;

-----------------------------------------------------------------------------
-- Loggers
-----------------------------------------------------------------------------

--  LOG OK
--
-- Log a success message to the log.  This procedure works in a chain.
-----------------------------------------------------------------------------

procedure log_ok( message : universal_string ) is
  context : constant chains.context := chains.chain_context;
  m : universal_string := message;
begin
  log_clean_message( m );
  case context is
  when chains.context_first =>
     log_first_part( message, "OK" );
  when chains.context_middle =>
     log_middle_part( m );
  when chains.context_last =>
     log_last_part( m );
  when chains.not_in_chain =>
     log_first_part( source_info.file & ": 0", "OK" );
     log_last_part( m );
  when others =>
     put_line( standard_error, "unexpect chain context" );
  end case;
end log_ok;


--  LOG INFO
--
-- Log an informational-severity message to the log.  This procedure works in
-- a chain.
-----------------------------------------------------------------------------

procedure log_info( message : universal_string ) is
  context : constant chains.context := chains.chain_context;
  m : universal_string := message;
begin
  case context is
  when chains.context_first =>
     log_first_part( message, "INFO" );
  when chains.context_middle =>
     log_middle_part( m );
  when chains.context_last =>
     log_last_part( m );
  when chains.not_in_chain =>
     log_first_part( source_info.file & ": 0", "INFO" );
     log_last_part( m );
  when others =>
     put_line( standard_error, "unexpect chain context" );
  end case;
end log_info;


--  LOG WARNING
--
-- Log a warning-severity message to the log.  This procedure works in a
-- chain.
-----------------------------------------------------------------------------

procedure log_warning( message : universal_string ) is
  context : constant chains.context := chains.chain_context;
  m : universal_string := message;
begin
  case context is
  when chains.context_first =>
     log_first_part( message, "WARNING" );
  when chains.context_middle =>
     log_middle_part( m );
  when chains.context_last =>
     log_last_part( m );
  when chains.not_in_chain =>
     log_first_part( source_info.file & ": 0", "WARNING" );
     log_end_part( m );
  when others =>
     put_line( standard_error, "unexpect chain context" );
  end case;
end log_warning;


--  LOG ERROR
--
-- Log an error-severity message to the log.  This procedure works in a
-- chain.
-----------------------------------------------------------------------------

procedure log_error( message : universal_string ) is
  context : constant chains.context := chains.chain_context;
  m : universal_string := message;
begin
  case context is
  when chains.context_first =>
     log_first_part( message, "ERROR" );
  when chains.context_middle =>
     log_middle_part( m );
  when chains.context_last =>
     log_last_part( m );
  when chains.not_in_chain =>
     log_first_part( source_info.file & ": 0", "ERROR" );
     log_end_part( m );
  when others =>
     put_line( standard_error, "unexpect chain context" );
  end case;
end log_error;

-----------------------------------------------------------------------------
-- Housekeeping
-----------------------------------------------------------------------------


--  LOG START
--
-- Reset logging variables and prepare to log.  Write the start message.
-----------------------------------------------------------------------------

procedure log_start( program_name : string; the_log_path : string;
  the_log_mode : log_modes ) is
begin
  log_level := 0;
  log_program_name := program_name;
  log_path := the_log_path;
  log_lock_file_path := log_path & ".lck";
  log_mode := the_log_mode;
  log_info( "Start " & log_program_name & " run" );
end log_start;


--  LOG END
--
-- Write the end message.  As a precaution, reset mode to write to standard
-- error.
-----------------------------------------------------------------------------

procedure log_end is
begin
  log_level := 0;
  log_info( "End " & log_program_name & " run" );
  log_mode := stderr_log;
end log_end;

-- vim: ft=spar
