separate;

-- LOGGING

-- Global Settings
--
-- Set echo logging to true to show log also to standard output
-----------------------------------------------------------------------------

echo_logging : boolean := false;

-- Private Settings
-----------------------------------------------------------------------------

type a_log_level is new natural;

log_file : file_type;
log_path : string;
log_string_header : string;
log_string_message : string;
log_program_name : string;
log_level : a_log_level;
log_indent_required : natural;
log_started_message : boolean := true;
log_width : constant integer := 75;
log_last_message : string := "";
log_dup_count : natural := 0;

-- LOG LEVEL START
--
-- Started a nested log level.  Increases the indent of log messages.
-----------------------------------------------------------------------------

function log_level_start return a_log_level is
  old_level : a_log_level := log_level;
begin
  log_level := @+1;
  return old_level;
end log_level_start;


-- LOG LEVEL END
--
-- Complete a nested log level.  Resets the indent of log messages.
-----------------------------------------------------------------------------

procedure log_level_end( old_level : a_log_level ) is begin
  log_level := old_level;
end log_level_end;


-----------------------------------------------------------------------------

-- LOG CLEAN MESSAGE
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


-- LOG FIRST PART
--
-- Build the first part of the log message: date, program and location.
-----------------------------------------------------------------------------

procedure log_first_part( m : universal_string; level_tag : string ) is
begin
  log_string_header := `date;` & ":";
  log_string_header := @ & strings.trim( strings.image( os.pid ) ) & ":"; --strings.image($$) & ":";
  log_string_header := @ & source_info.enclosing_entity & ":";
  log_string_header := @ & level_tag & ":";
  log_string_message := m & ":";
  log_indent_required := log_level * 2;
  log_started_message := false;
end log_first_part;


-- LOG MIDDLE PART
--
-- Build the middle part of the log message.  Indent and show the first
-- or next part of the user's message.
-----------------------------------------------------------------------------

procedure log_middle_part( m : universal_string ) is
begin
  if not log_started_message then
     while strings.length( log_string_header & log_string_message ) < log_width loop
        log_string_message := @ & ' ';
     end loop;
     if log_indent_required > 0 then
        log_string_message := @ & (log_indent_required * ' ');
        log_indent_required := 0;
     end if;
     log_string_message := @  &  ":";
     log_started_message;
  end if;
  log_string_message := @ & m;
end log_middle_part;


-- LOG LAST PART
--
-- Build the last part of the log message.  Indent (if needed) and show the
-- last of the user's message.
-----------------------------------------------------------------------------

procedure log_last_part( m : universal_string ) is
begin
  if not log_started_message then
     while strings.length( log_string_header & log_string_message ) < log_width loop
        log_string_message := @ & ' ';
     end loop;
     if log_indent_required > 0 then
        log_string_message := @ & (log_indent_required * ' ');
        log_indent_required := 0;
     end if;
     log_string_message := @  &  ":";
     log_started_message;
  end if;
  log_string_message := @ & m;
  if log_string_message = log_last_message then
     log_dup_count := @ + 1;
  else
     create( log_file, append_file, log_path );
     -- if there were dups, show the count
     if log_dup_count = 1 then
        put_line( log_file, log_string_header & log_last_message );
        if echo_logging then
           put_line( log_string_header & log_last_message );
        end if;
     elsif log_dup_count > 0 then
        -- TODO: missing location.  Location must be in duplicate string, but
        -- TODO: missing here
        -- TODO: missing indent
        -- TODO: probably only date should be in header
        put_line( log_file, log_string_header & "X:X: :... repeated" & strings.image( log_dup_count ) & " times" );
        if echo_logging then
           put_line( log_string_header & "X:X: :... repeated" & strings.image( log_dup_count ) & " times" );
        end if;
        log_dup_count := 0;
        -- now can print the new line
     end if;
     put_line( log_file, log_string_header & log_string_message );
     if echo_logging then
        put_line( log_string_header & log_string_message );
     end if;
     close( log_file );
     log_last_message := log_string_message;
  end if;
  log_string_message := "";
end log_last_part;

-----------------------------------------------------------------------------

-- LOG OK
--
-- Log a success-type message to the log.  This procedure works in a chain.
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
     log_first_part( source_info.file, "OK" );
     log_last_part( m );
  when others =>
     put_line( standard_error, "unexpect chain context" );
  end case;
end log_ok;


-- LOG INFO
--
-- Log an informational-type message to the log.  This procedure works in a
-- chain.
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
     log_first_part( source_info.file, "INFO" );
     log_last_part( m );
  when others =>
     put_line( standard_error, "unexpect chain context" );
  end case;
end log_info;


-- LOG WARNING
--
-- Log a warning-type message to the log.  This procedure works in a chain.
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
     log_first_part( source_info.file, "WARNING" );
     log_end_part( m );
  when others =>
     put_line( standard_error, "unexpect chain context" );
  end case;
end log_warning;


-- LOG ERROR
--
-- Log an error-type message to the log.  This procedure works in a chain.
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
     log_first_part( source_info.file, "ERROR" );
     log_end_part( m );
  when others =>
     put_line( standard_error, "unexpect chain context" );
  end case;
end log_error;


-- LOG START
--
-- Open the log file for logging.
-----------------------------------------------------------------------------

procedure log_start( program_name : string; the_log_path : string ) is
begin
  log_level := 0;
  log_program_name := program_name;
  log_path := the_log_path;
  log_info( "Start " & log_program_name & " run" );
end log_start;


-- LOG END
--
-- Close the log file.
-----------------------------------------------------------------------------

procedure log_end is
begin
  log_level := 0;
  log_info( "End " & log_program_name & " run" );
end log_end;

-- vim: ft=spar
