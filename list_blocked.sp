#!/usr/local/bin/spar

procedure list_blocked is
  pragma annotate( summary, "list_blocked" )
                @( description, "Write a report blocked IP's to " )
                @( description, "standard output." )
                @( author, "Ken O. Burtch" );
  pragma license( gplv3 );
  pragma software_model( shell_script );

  with separate "config/contributors.inc.sp";
  with separate "lib/world.inc.sp";
  with separate "config/config.inc.sp";
  with separate "lib/common.inc.sp";
  with separate "lib/blocking.inc.sp";

  pragma restriction( no_external_commands );

  offender_cursor : btree_io.cursor( an_offender );
  offender_key : string;
  offender : an_offender;
  j : json_string;

  countries_file : btree_io.file( country_data );
  country : country_data;
  country_name : string;
begin
  btree_io.open( countries_file, countries_path, countries_width, countries_width );
  btree_io.open( offender_file, offender_path, offender_buffer_width, offender_buffer_width );
  btree_io.open_cursor( offender_file, offender_cursor );
  btree_io.get_first( offender_file, offender_cursor, offender_key, offender );
  loop
     country_name := "unknown";
     begin
       btree_io.get( countries_file, string( offender.source_country ), country );
       country_name := country.common_name;
     exception when others => null; --- TODO: fix this
     end;
     put_line( offender.source_ip )
            @( "  DNS:       " & offender.source_name )
            @( "  Country:   " & country_name )
            @( "  Location:  " & offender.location )
            @( "  SSHD:     " & strings.image( offender.sshd_offenses ) )
            @( "  SMTP:     " & strings.image( offender.smtp_offenses ) )
            @( "  HTTP:     " & strings.image( offender.http_offenses ) );
     case offender.sshd_blocked is
     when unblocked_blocked =>
       put_line( "  SSHD Status:       unblocked" );
     when probation_blocked =>
       put_line( "  SSHD Status:       probation" );
     when short_blocked =>
       put_line( "  SSHD Status:       short blocked" );
     when banned_blocked =>
       put_line( "  SSHD Status:       banned" );
     when blacklisted_blocked =>
       put_line( "  SSHD Status:       blacklisted" );
     when others =>
       put_line( "  SSHD Status:       unknown" );
     end case;

     btree_io.get_next( offender_file, offender_cursor, offender_key, offender );
  end loop;
exception when others =>
  if btree_io.is_open( offender_file ) then
     btree_io.close_cursor( offender_file, offender_cursor );
     btree_io.close( offender_file );
  end if;
  if btree_io.is_open( countries_file ) then
     btree_io.close( countries_file );
  end if;
end list_blocked;

-- vim: ft=spar

