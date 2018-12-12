#!/usr/local/bin/spar

with separate "config/contributors.inc.sp";
with separate "lib/world.inc.sp";
with separate "config/config.inc.sp";

procedure list_logins is
  pragma annotate( summary, "list_logins" )
                @( description, "Write a report of login accounts to " )
                @( description, "standard output." )
                @( description, "Sort with 'sort -g -k2'." )
                @( author, "Ken O. Burtch" );
  pragma license( gplv3 );
  pragma software_model( shell_script );

  with separate "lib/logging.inc.sp";
  with separate "lib/common.inc.sp";
  with separate "lib/logins.inc.sp";

  pragma restriction( no_external_commands );

  sshd_logins_file : btree_io.file( a_sshd_login );
  sshd_cursor : btree_io.cursor( a_sshd_login );
  login_key : string;
  login : a_sshd_login;
  cnt : natural := 0;
begin
  btree_io.open( sshd_logins_file, string( sshd_logins_path ), sshd_logins_buffer_width, sshd_logins_buffer_width );
  btree_io.open_cursor( sshd_logins_file, sshd_cursor );
  btree_io.get_first( sshd_logins_file, sshd_cursor, login_key, login );
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
  loop
     cnt := @ + 1;
     btree_io.get_next( sshd_logins_file, sshd_cursor, login_key, login );
     --if login.count > 45 then
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
     --end if;
  end loop;
exception when others =>
  if btree_io.is_open( sshd_logins_file ) then
     btree_io.close_cursor( sshd_logins_file, sshd_cursor );
     btree_io.close( sshd_logins_file );
  end if;
  put( "logins:" ) @ ( cnt );
  new_line;
end list_logins;

-- vim: ft=spar

