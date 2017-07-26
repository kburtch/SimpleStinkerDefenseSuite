#!/usr/local/bin/spar

procedure list_logins is
  pragma annotate( summary, "list_logins" )
                @( description, "Write a report of login accounts to " )
                @( description, "standard output." )
                @( author, "Ken O. Burtch" );
  pragma license( gplv3 );
  pragma software_model( shell_script );

  with separate "config/contributors.inc.sp";
  with separate "lib/world.inc.sp";
  with separate "config/config.inc.sp";
  with separate "lib/common.inc.sp";

  pragma restriction( no_external_commands );

  bt : btree_io.file( a_sshd_login );
  btc : btree_io.cursor( a_sshd_login );
  key : string;
  login : a_sshd_login;
  cnt : natural := 0;
begin
  btree_io.open( bt, sshd_logins_path, sshd_logins_buffer_width, sshd_logins_buffer_width );
  btree_io.open_cursor( bt, btc );
  btree_io.get_first( bt, btc, key, login );
  put( login.username ) @ ( " " );
  put( login.count  ) @ ( " " );
  put( login.comment);
  new_line;
  loop
     cnt := @ + 1;
     btree_io.get_next( bt, btc, key, login );
     if login.count > 3 then
        put( login.username ) @ ( " " );
        put( login.count  ) @ ( " " );
        if login.kind = privileged_login then
           put( "privileged login " );
        elsif login.kind = service_login then
           put( "dictionary login " );
        elsif login.kind = existing_login then
           put( "existing login " );
        else
           put( "unknown kind " );
        end if;
        put( login.comment);
        new_line;
     end if;
  end loop;
exception when others =>
  btree_io.close_cursor( bt, btc );
  btree_io.close( bt );
  put( "logins:" ) @ ( cnt );
  new_line;
end list_logins;

-- vim: ft=spar

