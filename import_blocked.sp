#!/usr/local/bin/spar

procedure import_logins is
  pragma annotate( summary, "import_logins" )
                @( description, "Read the details of blocked IP's in JSON " )
                @( description, "format from a file." )
                @( author, "Ken O. Burtch" );
  pragma license( gplv3 );
  pragma software_model( shell_script );

  with separate "config/contributors.inc.sp";
  with separate "lib/world.inc.sp";
  with separate "config/config.inc.sp";
  with separate "lib/common.inc.sp";

  pragma restriction( no_external_commands );

  abt : btree_io.file( a_blocked_ip );
  blocked_ip : a_blocked_ip;
  j : json_string;
  json_file : file_type;
  json_path : string;
begin
  if command_line.argument_count /= 1 then
     put_line( standard_error, "expected an export file path argument" );
     command_line.set_exit_status( 192 );
     return;
  end if;
  json_path := command_line.argument( 1 );

  btree_io.open( abt, blocked_ip_path, blocked_ip_buffer_width, blocked_ip_buffer_width );
  open( json_file, in_file, json_path );
  while not end_of_file( json_file ) loop
     j := json_string( get_line( json_file ) );
     records.to_record( blocked_ip, j );
     btree_io.set( abt, string( blocked_ip.source_ip ), blocked_ip );
  end loop;
  btree_io.close( abt );
  close( json_file );
exception when others =>
  if btree_io.is_open( abt ) then
     btree_io.close( abt );
  end if;
  if is_open( json_file ) then
     close( json_file );
  end if;
  raise;
end import_logins;

-- vim: ft=spar

