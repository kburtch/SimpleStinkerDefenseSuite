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

  wget : limited command := "/bin/wget";

  traplist_filename : string := "bsdly.net.traplist";
  traplist_file : file_type;
  traplist_offender : string;
  traplist_message : constant string := "bsdly.net traplist";

  status : natural := 0;

  offender : ip_string;

  process_cnt : natural := 0;

  this_run_on : timestamp_string;

begin
  this_run_on := get_timestamp;

  setupWorld( "log/blocker.log", log_mode.file );
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
          foreign_record_and_block( offender, this_run_on, this_run_on, traplist_message );
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
