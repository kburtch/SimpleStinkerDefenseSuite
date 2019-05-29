#!/usr/local/bin/spar

with separate "config/contributors.inc.sp";
with separate "lib/world.inc.sp";
with separate "config/config.inc.sp";

procedure import_logins is
  pragma annotate( summary, "import_logins" )
                @( description, "Read the details of blocked IP's in JSON " )
                @( description, "format from a file." )
                @( author, "Ken O. Burtch" );
  pragma license( gplv3 );
  pragma software_model( shell_script );

  --with separate "../lib/logging.inc.sp";
  with separate "lib/common.inc.sp";
  with separate "lib/blocking.inc.sp";

type an_old_offender is record
     source_ip       : ip_string;
     source_name     : dns_string;
     source_country  : country_string;
     location        : string;
     sshd_blocked    : blocking_status;
     sshd_blocked_on : timestamp_string;
     sshd_offenses   : natural;
     smtp_blocked    : blocking_status;
     smtp_blocked_on : timestamp_string;
     smtp_offenses   : natural;
     spam_blocked    : blocking_status;
     spam_blocked_on : timestamp_string;
     spam_offenses   : natural;
     http_blocked    : blocking_status;
     http_blocked_on : timestamp_string;
     http_offenses   : natural;
     grace           : grace_count;
     created_on      : timestamp_string;
     logged_on       : timestamp_string;
     updated_on      : timestamp_string;
     data_type       : data_types;
end record;

  offender : an_offender;
  old_offender : an_old_offender;
  j : json_string;
  json_file : file_type;
  json_path : string;
  ts : timestamp_string;
begin
  if command_line.argument_count /= 1 then
     put_line( standard_error, "expected an export file path argument" );
     command_line.set_exit_status( 192 );
     return;
  end if;
  json_path := command_line.argument( 1 );

  ts := get_timestamp;

  btree_io.open( offender_file, string(offender_path), offender_buffer_width, offender_buffer_width );
  open( json_file, in_file, json_path );
  while not end_of_file( json_file ) loop
     -- Block is a workaround for symbol table overflow bug
     begin
     j := json_string( get_line( json_file ) );
     records.to_record( old_offender, j );
     -- source_ip       : ip_string;
     -- source_name     : dns_string;
     -- source_country  : country_string;
     -- location        : string;
     -- sshd_blocked    : blocking_status;
     -- sshd_blocked_on : timestamp_string;
     -- sshd_offences   : natural;
     -- mail_blocked    : blocking_status;
     -- mail_blocked_on : timestamp_string;
     -- mail_offences   : natural;
     -- spam_blocked    : blocking_status;
     -- spam_blocked_on : timestamp_string;
     -- spam_offences   : natural;
     -- http_blocked    : blocking_status;
     -- http_blocked_on : timestamp_string;
     -- http_offences   : natural;
     -- grace           : grace_count;
     -- created_on      : timestamp_string;
     -- logged_on       : timestamp_string;
     -- updated_on      : timestamp_string;
     -- exists_as       : a_login_existence;
     -- sourced_from    : string;
     -- data_type       : data_types;

     offender.source_ip := old_offender.source_ip;
     offender.source_name := old_offender.source_name;
     offender.source_country := old_offender.source_country;
     offender.location := old_offender.location;
     offender.sshd_blocked := old_offender.sshd_blocked;
     offender.sshd_blocked_on := old_offender.sshd_blocked_on;
     offender.sshd_offences := old_offender.sshd_offenses;
     offender.mail_blocked := old_offender.smtp_blocked;
     offender.mail_blocked_on := old_offender.smtp_blocked_on;
     offender.mail_offences := old_offender.smtp_offenses;
     offender.spam_blocked := unblocked_blocked;
     offender.spam_blocked_on := ts;
     offender.spam_offences := 0;
     offender.http_blocked := old_offender.http_blocked;
     offender.http_blocked_on := old_offender.http_blocked_on;
     offender.http_offences := old_offender.http_offenses;
     offender.grace := old_offender.grace;
     offender.created_on := old_offender.created_on;
     offender.logged_on := old_offender.logged_on;
     offender.updated_on := old_offender.updated_on;
     offender.sourced_from := "";
     offender.data_type := old_offender.data_type;
     btree_io.set( offender_file, string( offender.source_ip ), offender );
     end;
  end loop;
  btree_io.close( offender_file );
  close( json_file );
exception when others =>
  if btree_io.is_open( offender_file ) then
     btree_io.close( offender_file );
  end if;
  if is_open( json_file ) then
     close( json_file );
  end if;
  raise;
end import_logins;

-- vim: ft=spar

