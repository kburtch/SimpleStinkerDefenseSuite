#!/usr/local/bin/spar

procedure import_logins is
  pragma annotate( summary, "import_logins" )
                @( description, "Read the details of login accounts in JSON " )
                @( description, "format from a file." )
                @( author, "Ken O. Burtch" );
  pragma license( gplv3 );
  pragma software_model( shell_script );

  with separate "config/contributors.inc.sp";
  with separate "lib/world.inc.sp";
  with separate "config/config.inc.sp";
  with separate "lib/common.inc.sp";

  pragma restriction( no_external_commands );

  bt : btree_io.file( a_sshd_login );
  key : string;
  login : a_sshd_login;
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

  btree_io.open( bt, sshd_logins_path, sshd_logins_buffer_width, sshd_logins_buffer_width );
  open( json_file, in_file, json_path );
  while not end_of_file( json_file ) loop
     j := json_string( get_line( json_file ) );
     records.to_record( login, j );
     btree_io.set( bt, string( login.username ), login );
  end loop;
  btree_io.close( bt );
  close( json_file );
exception when others =>
  if btree_io.is_open( bt ) then
     btree_io.close( bt );
  end if;
  if is_open( json_file ) then
     close( json_file );
  end if;
  raise;
end import_logins;

-- vim: ft=spar

