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
log_string : string;
log_program_name : string;
log_level : a_log_level;
log_indent_required : natural;


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


-- LOG CLEAN MESSAGE
--
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


-- LOG OK
--
-- Log a success-type message to the log.  This procedure works in a chain.
-----------------------------------------------------------------------------

procedure log_ok( message : universal_string ) is
  context : constant chains.context := chains.chain_context;
  m : universal_string := message;
begin
  case context is
  when chains.context_first =>
     log_string := `date;` & ":";
     log_string := @ & source_info.enclosing_entity & strings.image($$) & ":";
     log_string := @ & "OK:";
     log_string := @ & m &  ":";
     log_indent_required := log_level * 2;
  when chains.context_middle =>
     if log_indent_required > 0 then
        log_string := @ & (log_indent_required * ' ');
        log_indent_required := 0;
     end if;
     log_clean_message( m );
     log_string := @ & m;
  when chains.context_last =>
     if log_indent_required > 0 then
        log_string := @ & (log_indent_required * ' ');
        log_indent_required := 0;
     end if;
     log_clean_message( m );
     log_string := @ & m;
     create( log_file, append_file, log_path );
     put_line( log_file, log_string );
     if echo_logging then
        put_line( log_string );
     end if;
     close( log_file );
  when chains.not_in_chain =>
     log_string := `date;` & ":";
     log_string := @ & source_info.enclosing_entity & strings.image($$) & ":";
     log_string := @ & "OK:";
     log_string := @ & source_info.file &  ":";
     log_indent_required := log_level * 2;
     if log_indent_required > 0 then
        log_string := @ & ( log_indent_required * ' ');
        log_indent_required := 0;
     end if;
     log_clean_message( m );
     log_string := @ & m;
     create( log_file, append_file, log_path );
     put_line( log_file, log_string );
     if echo_logging then
        put_line( log_string );
     end if;
     close( log_file );
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
     log_string := `date;` & ":";
     log_string := @ & source_info.enclosing_entity & strings.image($$) & ":";
     log_string := @ & "INFO:";
     log_string := @ & m &  ":";
     log_indent_required := log_level * 2;
  when chains.context_middle =>
     if log_indent_required > 0 then
        log_string := @ & (log_indent_required * ' ');
        log_indent_required := 0;
     end if;
     log_clean_message( m );
     log_string := @ & m;
  when chains.context_last =>
     if log_indent_required > 0 then
        log_string := @ & (log_indent_required * ' ');
        log_indent_required := 0;
     end if;
     log_clean_message( m );
     log_string := @ & m;
     create( log_file, append_file, log_path );
     put_line( log_file, log_string );
     if echo_logging then
        put_line( log_string );
     end if;
     close( log_file );
  when chains.not_in_chain =>
     log_string := `date;` & ":";
     log_string := @ & source_info.enclosing_entity & strings.image($$) & ":";
     log_string := @ & "INFO:";
     log_string := @ & source_info.file &  ":";
     log_indent_required := log_level * 2;
     if log_indent_required > 0 then
        log_string := @ & ( log_indent_required * ' ');
        log_indent_required := 0;
     end if;
     log_clean_message( m );
     log_string := @ & m;
     create( log_file, append_file, log_path );
     put_line( log_file, log_string );
     if echo_logging then
        put_line( log_string );
     end if;
     close( log_file );
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
     log_string := `date;` & ":";
     log_string := @ & source_info.enclosing_entity & strings.image($$) & ":";
     log_string := @ & "WARNING:";
     log_string := @ & m &  ":";
     log_indent_required := log_level * 2;
  when chains.context_middle =>
     if log_indent_required > 0 then
        log_string := @ & (log_indent_required * ' ');
        log_indent_required := 0;
     end if;
     log_clean_message( m );
     log_string := @ & m;
  when chains.context_last =>
     if log_indent_required > 0 then
        log_string := @ & (log_indent_required * ' ');
        log_indent_required := 0;
     end if;
     log_clean_message( m );
     log_string := @ & m;
     create( log_file, append_file, log_path );
     put_line( log_file, log_string );
     if echo_logging then
        put_line( log_string );
     end if;
     close( log_file );
  when chains.not_in_chain =>
     log_string := `date;` & ":";
     log_string := @ & source_info.enclosing_entity & strings.image($$) & ":";
     log_string := @ & "WARNING:";
     log_string := @ & source_info.file &  ":";
     log_indent_required := log_level * 2;
     if log_indent_required > 0 then
        log_string := @ & (log_indent_required * ' ');
        log_indent_required := 0;
     end if;
     log_clean_message( m );
     log_string := @ & m;
     create( log_file, append_file, log_path );
     put_line( log_file, log_string );
     if echo_logging then
        put_line( log_string );
     end if;
     close( log_file );
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
     log_string := `date;` & ":";
     log_string := @ & source_info.enclosing_entity & strings.image($$) & ":";
     log_string := @ & "ERROR:";
     log_string := @ & m &  ":";
     log_indent_required := log_level * 2;
  when chains.context_middle =>
     if log_indent_required > 0 then
        log_string := @ & (log_indent_required * ' ');
        log_indent_required := 0;
     end if;
     log_clean_message( m );
     log_string := @ & m;
  when chains.context_last =>
     if log_indent_required > 0 then
        log_string := @ & (log_indent_required * ' ');
        log_indent_required := 0;
     end if;
     log_clean_message( m );
     log_string := @ & m;
     create( log_file, append_file, log_path );
     put_line( log_file, log_string );
     if echo_logging then
        put_line( log_string );
     end if;
     close( log_file );
  when chains.not_in_chain =>
     log_string := `date;` & ":";
     log_string := @ & source_info.enclosing_entity & strings.image($$) & ":";
     log_string := @ & "ERROR:";
     log_string := @ & source_info.file &  ":";
     log_indent_required := log_level * 2;
     if log_indent_required > 0 then
        log_string := @ & (log_indent_required * ' ');
        log_indent_required := 0;
     end if;
     log_clean_message( m );
     log_string := @ & m;
     create( log_file, append_file, log_path );
     put_line( log_file, log_string );
     if echo_logging then
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
