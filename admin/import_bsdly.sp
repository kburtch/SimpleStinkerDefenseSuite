#!/usr/local/bin/spar

with separate "config/contributors.inc.sp";
with separate "lib/world.inc.sp";
with separate "config/config.inc.sp";

procedure import_bsdly is
  pragma annotate( summary, "import_bsdly" )
                @( description, "Import Bsdly blocked IP list" )
                @( author, "Ken O. Burtch" );
  pragma license( gplv3 );
  pragma software_model( shell_script );

  with separate "lib/common.inc.sp";
  with separate "lib/blocking.inc.sp";

opt_daemon  : boolean := false;   -- true of -D used

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

  wget : limited command := "/bin/wget";

  traplist_filename : string := "bsdly.net.traplist";
  traplist_file : file_type;
  traplist_offender : ip_string;
  traplist_message : constant string := "bsdly.net traplist spammer";

  status : natural := 0;

  process_cnt : natural := 0;

  this_run_on : timestamp_string;

  import_log_mode : logs.log_modes := log_mode.echo;

begin
  this_run_on := get_timestamp;

  -- Process command options

  if handle_command_options then
     command_line.set_exit_status( 1 );
     return;
  end if;

  -- In daemon mode, only log to log file

  if opt_daemon then
     import_log_mode := log_mode.file;
  end if;

  setupWorld( "log/blocker.log", import_log_mode );
  startup_blocking;

  if files.exists( traplist_filename ) then
     logs.error( "download file already exists - erase first" );
  end if;

  -- Download the latest traplist

  logs.info( "downloading bsdly.net list" );
  wget -q "https://www.bsdly.net/~peter/bsdly.net.traplist";
  status := $?;
  if status /= 0 then
     logs.error( "download failed with status " & strings.image( status ) );
  end if;
  if not files.exists( traplist_filename ) then
     logs.error( "download failed - file not found" );
  end if;

  -- Import the traplist.
  -- we mark them as spammers.  however the list includes all kinds of
  -- attackers and may not actually be spammers.

  logs.info( "importing bsdly.net list" );
  open( traplist_file, in_file, traplist_filename );
  while not end_of_file( traplist_file ) loop
    traplist_offender := get_line( traplist_file );
    if strings.length( traplist_offender ) > 0 then
       if strings.element( traplist_offender, 1 ) /= '#' then
          foreign_record_and_block( traplist_offender, this_run_on, this_run_on, traplist_message );
          process_cnt := @ + 1;
       end if;
    end if;
  end loop;
  delete( traplist_file );

  logs.ok( "Processed" ) @ ( strings.image( process_cnt ) ) @ ( " IP numbers" );

exception when others =>
  logs.error( exceptions.exception_info );
  if is_open( traplist_file ) then
     close( traplist_file );
  end if;
  shutdown_blocking;
  shutdownWorld;
  raise;
end import_bsdly;

-- vim: ft=spar
