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

  with separate "lib/logging.inc.sp";
  with separate "lib/common.inc.sp";
  with separate "lib/blocking.inc.sp";

  pragma restriction( no_external_commands );

  offender : an_offender;
  j : json_string;
  json_file : file_type;
  json_path : string;
begin
  --if command_line.argument_count > 1 then
  --   put_line( standard_error, "expected an export file path argument" );
  --   command_line.set_exit_status( 192 );
  --   return;
  --elsif command_line.argument_count > 1 then
  --   json_path := command_line.argument( 1 );
  --end if;

  btree_io.open( offender_file, string( offender_path ), offender_buffer_width, offender_buffer_width );
  --open( json_file, in_file, json_path );
  while not end_of_file( json_file ) loop
     if json_path = "" then
        j := json_string( get_line );
     else
        j := json_string( get_line( json_file ) );
     end if;
     records.to_record( offender, j );
     btree_io.set( offender_file, string( offender.source_ip ), offender );
  end loop;
  btree_io.close( offender_file );
  close( json_file );
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

