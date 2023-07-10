#!/usr/local/bin/spar

with separate "config/contributors.inc.sp";
with separate "lib/world.inc.sp";
with separate "config/config.inc.sp";

procedure import_blocked is
  pragma annotate( summary, "import_blocked" )
                @( description, "Read the details of blocked IP's in JSON " )
                @( description, "format from a file." )
                @( author, "Ken O. Burtch" );
  pragma license( gplv3 );
  pragma software_model( shell_script );

  with separate "lib/common.inc.sp";
  with separate "lib/blocking.inc.sp";

  offender : an_offender;
  j : json_string;
  json_file : file_type;
  json_path : string;
  rec_cnt : natural := 1;
  ts : timestamp_string;
begin
  if command_line.argument_count > 1 then
     put_line( standard_error, "expected an json file path argument" );
     command_line.set_exit_status( 192 );
     return;
  elsif command_line.argument_count = 1 then
     json_path := command_line.argument( 1 );
  end if;

  if files.exists( string( offender_path ) ) then
     btree_io.open( offender_file, string( offender_path ), offender_buffer_width, offender_buffer_width );
  else
     btree_io.create( offender_file, string( offender_path ), offender_buffer_width, offender_buffer_width );
  end if;
  if json_path /= "" then
     open( json_file, in_file, json_path );
  end if;

  ts := get_timestamp;
  loop
     if json_path = "" then
        exit when end_of_file( current_input );
        -- by explicitly choosing current input, it suppresses echoing
        -- to the terminal.
        begin
           j := json_string( get_line( current_input ) );
        exception when others =>
           -- this will be file not open when input is exhausted
           exit;
        end;
     else
        exit when end_of_file( json_file );
        j := json_string( get_line( json_file ) );
     end if;
     -- KLUDGE: This should not be needed.
     if strings.head( j, 1 ) = "." then
        j := strings.delete( j, 1, 1 );
     end if;
     begin
        offender.updated_on := ts;
        records.to_record( offender, j );
     exception when others =>
        put_line( standard_error, "Error in JSON record" &
          strings.image( rec_cnt ) );
        raise;
     end;
     btree_io.set( offender_file, string( offender.source_ip ), offender );
     rec_cnt := @+1;
  end loop;
  if btree_io.is_open( offender_file ) then
     btree_io.close( offender_file );
  end if;
  if is_open( json_file ) then
     close( json_file );
  end if;
  put_line( "Offending IP's imported:" & strings.image( rec_cnt ) );
exception when others =>
  if btree_io.is_open( offender_file ) then
     btree_io.close( offender_file );
  end if;
  if is_open( json_file ) then
     close( json_file );
  end if;
  raise;
end import_blocked;

-- vim: ft=spar

