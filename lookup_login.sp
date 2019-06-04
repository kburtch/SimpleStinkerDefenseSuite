#!/usr/local/bin/spar

with separate "config/contributors.inc.sp";
with separate "lib/world.inc.sp";
with separate "config/config.inc.sp";

procedure lookup_login is
  pragma annotate( summary, "lookup_login username" )
                @( description, "Write a report on a single username" )
                @( description, "to standard output." )
                @( author, "Ken O. Burtch" )
                @( param, "username - the user login" );
  pragma license( gplv3 );
  pragma software_model( shell_script );

  with separate "lib/common.inc.sp";
  with separate "lib/logins.inc.sp";
  with separate "lib/reports_login.inc.sp";

procedure usage is
begin
  help( source_info.enclosing_entity );
end usage;

login_key : string;
must_quit    : boolean := false;

procedure handle_command_options( quit : out boolean ) is
  arg_pos : natural := 1;
  arg : string;
begin
  quit := false;
  while arg_pos <= command_line.argument_count loop
    arg := command_line.argument( arg_pos );
    if arg = "-h" or arg = "--help" then
       usage;
       quit;
    elsif arg_pos = command_line.argument_count then
       login_key := arg;
    else
       put_line( standard_error, "unknown option: " & arg );
       quit;
    end if;
    arg_pos := @+1;
  end loop;
  if login_key = "" and not quit then
     put_line( standard_error, "an ip number is required" );
     quit;
  end if;
end handle_command_options;

  sshd_logins_file : btree_io.file( a_sshd_login );
  login : a_sshd_login;
  --cnt : natural := 0;
  found : boolean := false;
begin

  -- Process command options

  handle_command_options( must_quit );
  if must_quit  then
     command_line.set_exit_status( 1 );
     return;
  end if;

  btree_io.open( sshd_logins_file, string( sshd_logins_path ), sshd_logins_buffer_width, sshd_logins_buffer_width );

  begin
    btree_io.get( sshd_logins_file, login_key, login );
    found;
  exception when others =>
    found := false;
  end;

  if not found then
     put_line( login_key & " is not known" );
     if btree_io.is_open( sshd_logins_file ) then
        btree_io.close( sshd_logins_file );
     end if;
     return;
  end if;

  login_report( login );
  btree_io.close( sshd_logins_file );
exception when others =>
  if btree_io.is_open( sshd_logins_file ) then
     btree_io.close( sshd_logins_file );
  end if;
  raise;
end lookup_login;

-- vim: ft=spar

