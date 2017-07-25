#!/usr/local/bin/spar

procedure export_logins is
  pragma annotate( summary, "export_logins" )
                @( description, "Write the details of login accounts in JSON " )
                @( description, "format to standard output." )
                @( author, "Ken O. Burtch" );
  pragma license( gplv3 );
  pragma software_model( shell_script );

  with separate "lib/world.inc.sp";
  with separate "config/config.inc.sp";
  with separate "lib/common.inc.sp";

  pragma restriction( no_external_commands );

  bt : btree_io.file( a_sshd_login );
  btc : btree_io.cursor( a_sshd_login );
  key : string;
  login : a_sshd_login;
  j : json_string;
begin
  btree_io.open( bt, sshd_logins_path, sshd_logins_buffer_width, sshd_logins_buffer_width );
  btree_io.open_cursor( bt, btc );
  btree_io.get_first( bt, btc, key, login );
  records.to_json( j, login );
  put_line( j );
  loop
     btree_io.get_next( bt, btc, key, login );
     records.to_json( j, login );
     put_line( j );
  end loop;
exception when others =>
  btree_io.close_cursor( bt, btc );
  btree_io.close( bt );
end export_logins;

-- vim: ft=spar

