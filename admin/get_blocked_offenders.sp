#!/usr/local/bin/spar

with separate "config/contributors.inc.sp";
with separate "lib/world.inc.sp";
with separate "config/config.inc.sp";

procedure get_blocked_offenders is
  pragma annotate( summary, "get_blocked_offenders" )
                @( description, "Display all blocked offenders from the blocking database." )
                @( description, "Include a total at the end of the report." )
                @( author, "Ken O. Burtch" );
  pragma license( gplv3 );
  pragma software_model( shell_script );

  with separate "lib/common.inc.sp";
  with separate "lib/blocking.inc.sp";

  pragma restriction( no_external_commands );

  offender_cursor : btree_io.cursor( an_offender );
  offender_key : string;
  offender : an_offender;
  offender_json : json_string;
  block_count : natural := 0;
begin
  btree_io.open( offender_file, string( offender_path ), offender_buffer_width, offender_buffer_width );
  btree_io.open_cursor( offender_file, offender_cursor );
  btree_io.get_first( offender_file, offender_cursor, offender_key, offender );
  loop
     records.to_json( offender_json, offender );
     if offender.sshd_blocked > probation_blocked or
        offender.mail_blocked > probation_blocked or
        offender.http_blocked > probation_blocked or
        offender.spam_blocked > probation_blocked then
        put_line( offender.source_ip );
        block_count := @ + 1;
     end if;
     btree_io.get_next( offender_file, offender_cursor, offender_key, offender );
  end loop;
exception when others =>
  put_line( "blocked " & strings.image( block_count ) );
  if btree_io.is_open( offender_file ) then
     btree_io.close_cursor( offender_file, offender_cursor );
     btree_io.close( offender_file );
  end if;
end get_blocked_offenders;

-- vim: ft=spar

