#!/usr/local/bin/spar

procedure export_logins is
  pragma annotate( summary, "export_logins" )
                @( description, "Write the details of login accounts in JSON " )
                @( description, "format to standard output." )
                @( author, "Ken O. Burtch" );
  pragma license( gplv3 );
  pragma software_model( shell_script );

  with separate "config/contributors.inc.sp";
  with separate "lib/world.inc.sp";
  with separate "config/config.inc.sp";
  with separate "lib/common.inc.sp";

  pragma restriction( no_external_commands );

  sshd_logins_file : btree_io.file( a_sshd_login );
  sshd_cursor : btree_io.cursor( a_sshd_login );
  login_key : string;
  login : a_sshd_login;
  j : json_string;
begin
  btree_io.open( sshd_logins_file, sshd_logins_path, sshd_logins_buffer_width, sshd_logins_buffer_width );
  btree_io.open_cursor( sshd_logins_file, sshd_cursor );
  btree_io.get_first( sshd_logins_file, sshd_cursor, login_key, login );
  records.to_json( j, login );
  put_line( j );
  loop
     btree_io.get_next( sshd_logins_file, sshd_cursor, login_key, login );
     records.to_json( j, login );
     put_line( j );
  end loop;
exception when others =>
  if btree_io.is_open( sshd_logins_file ) then
     btree_io.close_cursor( sshd_logins_file, sshd_cursor );
     btree_io.close( sshd_logins_file );
  end if;
end export_logins;

-- vim: ft=spar

