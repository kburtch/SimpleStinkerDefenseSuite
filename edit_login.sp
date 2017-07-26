#!/usr/local/bin/spar

procedure edit_login is
  pragma annotate( summary, "edit_login" )
                @( description, "Edit a login's details" )
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
  cnt : natural := 0;
  s   : string;
begin
  put( "Username? " );
  key := get_line;
  if key = "" then
     return;
  end if;

  btree_io.open( bt, sshd_logins_path, sshd_logins_buffer_width, sshd_logins_buffer_width );
  btree_io.get( bt, key, login );

  put( "Username: " ) @ ( login.username ); new_line;
  put( "Count:    " ) @ ( login.count  ); new_line;
  put( "Kind:     " ) @ ( login.kind   ); new_line;
  put( "Comment:  " ) @ ( login.comment ); new_line;
  new_line;
  put_line( " 0 privileged_login, 1 service_login, 2 dictionary_login," );
  put_line( " 3 existing_login, 4 unknown_login_kind" );
  put( "New Kind? " );
  s := get_line;
  s := strings.trim( @ );
  case s is
  when "0" => login.kind := privileged_login;
  when "1" => login.kind := service_login;
  when "2" => login.kind := dictionary_login;
  when "3" => login.kind := existing_login;
  when "4" => login.kind := unknown_login_kind;
  when others => put_line( "I don't know that kind" );
  end case;
  login.comment := comment_string( strings.trim( s ) );
  put( "New Reason? " );
  login.comment := get_line;
  login.comment := comment_string( strings.trim( @ ) );
  if login.comment /= "" then
     btree_io.replace( bt, key, login );
  end if;
  btree_io.close( bt );
end edit_login;

-- vim: ft=spar

