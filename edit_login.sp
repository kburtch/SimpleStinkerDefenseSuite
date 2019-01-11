#!/usr/local/bin/spar

with separate "config/contributors.inc.sp";
with separate "lib/world.inc.sp";
with separate "config/config.inc.sp";

procedure edit_login is
  pragma annotate( summary, "edit_login" )
                @( description, "Edit a login's details" )
                @( author, "Ken O. Burtch" );
  pragma license( gplv3 );
  pragma software_model( shell_script );

  with separate "lib/logging.inc.sp";
  with separate "lib/common.inc.sp";
  with separate "lib/logins.inc.sp";

  pragma restriction( no_external_commands );

  sshd_logins_file : btree_io.file( a_sshd_login );
  key : string;
  login : a_sshd_login;
  --cnt : natural := 0;
  s   : string;
begin
  put( "Username? " );
  key := get_line;
  if key = "" then
     return;
  end if;

  btree_io.open( sshd_logins_file, string( sshd_logins_path ), sshd_logins_buffer_width, sshd_logins_buffer_width );
  btree_io.get( sshd_logins_file, key, login );

  put( "Username: " ) @ ( login.username ); new_line;
  put( "Count:    " ) @ ( login.count  ); new_line;
  put( "Kind:     " ) @ ( login.kind   ); new_line;
  put( "Comment:  " ) @ ( login.comment ); new_line;
  new_line;
  put_line( " 0 privileged_login, 1 service_login, 2 dictionary_login," );
  put_line( " 3 existing_login, 4 unknown_login_kind, 5 role_login," );
  put_line( " 6 guest_login, 7 data_service_login, 8 calling_card" );
  put( "New Kind? " );
  s := get_line;
  s := strings.trim( @ );
  case s is
  when "0" => login.kind := privileged_login;
  when "1" => login.kind := service_login;
  when "2" => login.kind := dictionary_login;
  when "3" => login.kind := existing_login;
  when "4" => login.kind := unknown_login_kind;
  when "5" => login.kind := role_login;
  when "6" => login.kind := guest_login;
  when "7" => login.kind := data_service_login;
  when "8" => login.kind := calling_card;
  when others => put_line( "I don't know that kind" );
  end case;
  login.comment := comment_string( strings.trim( s ) );
  put( "New Reason? ('x' aborts) " );
  login.comment := get_line;
  login.comment := comment_string( strings.trim( @ ) );
  if login.comment /= "x" then
     btree_io.replace( sshd_logins_file, key, login );
  end if;
  btree_io.close( sshd_logins_file );
end edit_login;

-- vim: ft=spar

