#!/usr/local/bin/spar

procedure blacklist_ip is
  pragma annotate( summary, "blacklist_ip" )
                @( description, "Blacklist an IP number" )
                @( author, "Ken O. Burtch" );
  pragma license( gplv3 );
  pragma software_model( shell_script );

  with separate "config/contributors.inc.sp";
  with separate "lib/world.inc.sp";
  with separate "config/config.inc.sp";
  with separate "lib/common.inc.sp";
  with separate "lib/blocking.inc.sp";

  pragma restriction( no_external_commands );

  source_ip : ip_string;
  offender : an_offender;
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

  btree_io.open( offender_file, offender_path, offender_buffer_width, offender_buffer_width );

  if btree_io.has_element( offender_file, string( source_ip ) ) then
     btree_io.get( offender_file, string( source_ip ), offender );
  else
     offender.source_ip       := source_ip;
     offender.source_name     := "";
     offender.source_country  := "";
     offender.location        := "";
     offender.sshd_offenses   := 0;
     offender.smtp_offenses   := 0;
     offender.http_offenses   := 0;
  end if;

  offender.sshd_blocked    := blacklisted_blocked;
  offender.sshd_blocked_on := this_run_on;
  offender.smtp_blocked    := blacklisted_blocked;
  offender.smtp_blocked_on := this_run_on;
  offender.http_blocked    := blacklisted_blocked;
  offender.http_blocked_on := this_run_on;
  offender.created_on      := this_run_on;
  offender.logged_on       := this_run_on;
  offender.updated_on      := this_run_on;

  btree_io.set( offender_file, string( source_ip ), offender );
  btree_io.close( offender_file );
  put_line( source_ip & " has been blacklisted" );
exception when others =>
  if btree_io.is_open( offender_file ) then
     btree_io.close( offender_file );
  end if;
  raise;
end blacklist_ip;

-- vim: ft=spar

