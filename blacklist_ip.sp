#!/usr/local/bin/spar

procedure blacklist_ip is
  pragma annotate( summary, "blacklist_ip" )
                @( description, "Blacklist an IP number" )
                @( author, "Ken O. Burtch" );
  pragma license( gplv3 );

  with separate "world.inc.sp";

  pragma restriction( no_external_commands );

  blocked_ip_file : btree_io.file( a_blocked_ip );
  source_ip : ip_string;
  ab : a_blocked_ip;
  this_run_on : timestamp_string;
begin

  if command_line.argument_count /= 1 then
     put_line( standard_error, "expected an ip number argument" );
     command_line.set_exit_status( 192 );
     return;
  end if;
  source_ip := ip_string( command_line.argument( 1 ) );

  -- TODO: validate IP;

  this_run_on := get_timestamp;

  btree_io.open( blocked_ip_file, blocked_ip_path, blocked_ip_buffer_width, blocked_ip_buffer_width );

  if btree_io.has_element( blocked_ip_file, string( source_ip ) ) then
     btree_io.get( blocked_ip_file, string( source_ip ), ab );
  else
     ab.source_ip       := source_ip;
     ab.source_name     := "";
     ab.source_country  := "";
     ab.location        := "";
     ab.sshd_offenses   := 0;
     ab.smtp_offenses   := 0;
     ab.http_offenses   := 0;
  end if;

  ab.sshd_blocked    := blacklisted_blocked;
  ab.sshd_blocked_on := this_run_on;
  ab.smtp_blocked    := blacklisted_blocked;
  ab.smtp_blocked_on := this_run_on;
  ab.http_blocked    := blacklisted_blocked;
  ab.http_blocked_on := this_run_on;
  ab.created_on      := this_run_on;
  ab.logged_on       := this_run_on;
  ab.updated_on      := this_run_on;

  btree_io.set( blocked_ip_file, string( source_ip ), ab );
  btree_io.close( blocked_ip_file );
  put_line( source_ip & " has been blacklisted" );
exception when others =>
  if btree_io.is_open( blocked_ip_file ) then
     btree_io.close( blocked_ip_file );
  end if;
  raise;
end blacklist_ip;

-- vim: ft=spar

