#!/usr/local/bin/spar

with separate "config/contributors.inc.sp";
with separate "lib/world.inc.sp";
with separate "config/config.inc.sp";

procedure import_logins is
  pragma annotate( summary, "import_logins" )
                @( description, "Read the details of login accounts in JSON " )
                @( description, "format from a file." )
                @( author, "Ken O. Burtch" );
  pragma license( gplv3 );
  pragma software_model( shell_script );

  with separate "lib/common.inc.sp";
  with separate "lib/logins.inc.sp";

  pragma restriction( no_external_commands );

  bt : btree_io.file( a_sshd_login );
  --key : string;
  login : a_sshd_login;
  j : json_string;
  json_file : file_type;
  json_path : string;
  rec_cnt : natural := 1;
begin
  if command_line.argument_count > 1 then
     put_line( standard_error, "expected an json file path argument" );
     command_line.set_exit_status( 192 );
     return;
  elsif command_line.argument_count > 1 then
     json_path := command_line.argument( 1 );
  end if;

  if files.exists( string( sshd_logins_path ) ) then
     btree_io.open( bt, string( sshd_logins_path ), sshd_logins_buffer_width, sshd_logins_buffer_width );
  else
     btree_io.create( bt, string( sshd_logins_path ), sshd_logins_buffer_width, sshd_logins_buffer_width );
  end if;
  if json_path /= "" then
     open( json_file, in_file, json_path );
  end if;

  loop
     if json_path = "" then
        exit when end_of_file( current_input );
        -- by explicitly choosing current input, it suppresses echoing
        -- to the terminal.
        begin
           j := json_string( get_line( current_input ) );
        exception when others =>
           -- this will be file not open when input is exhausted
           exit;
        end;
     else
        exit when end_of_file( json_file );
        j := json_string( get_line( json_file ) );
     end if;
     -- KLUDGE: This should not be needed.
     if strings.head( j, 1 ) = "." then
        j := strings.delete( j, 1, 1 );
     end if;
     begin
        records.to_record( login, j );
     exception when others =>
        put_line( standard_error, "Error in JSON record" &
          strings.image( rec_cnt ) );
        raise;
     end;
     btree_io.set( bt, string( login.username ), login );
     rec_cnt := @+1;
  end loop;
  if btree_io.is_open( bt ) then
     btree_io.close( bt );
  end if;
  if is_open( json_file ) then
     close( json_file );
  end if;
  put_line( "Logins imported:" & strings.image( rec_cnt ) );
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

