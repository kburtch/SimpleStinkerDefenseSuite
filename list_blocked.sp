#!/usr/local/bin/spar

with separate "config/contributors.inc.sp";
with separate "lib/world.inc.sp";
with separate "config/config.inc.sp";

procedure list_blocked is
  pragma annotate( summary, "list_blocked" )
                @( description, "Write a report blocked IP's to " )
                @( description, "standard output." )
                @( author, "Ken O. Burtch" );
  pragma license( gplv3 );
  pragma software_model( shell_script );

  with separate "lib/logging.inc.sp";
  with separate "lib/common.inc.sp";
  with separate "lib/blocking.inc.sp";
  with separate "lib/countries.inc.sp";

  pragma restriction( no_external_commands );

  offender_cursor : btree_io.cursor( an_offender );
  offender_key : string;
  offender : an_offender;
  j : json_string;

  countries_file : btree_io.file( country_data );
  country : country_data;
  country_name : string;
begin
  btree_io.open( countries_file, string( countries_path ), countries_width, countries_width );
  btree_io.open( offender_file, string( offender_path ), offender_buffer_width, offender_buffer_width );
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
            @( "  SPAM:     " & strings.image( offender.spam_offenses ) )
            @( "  HTTP:     " & strings.image( offender.http_offenses ) );
     if offender.sshd_blocked = unblocked_blocked and
        offender.smtp_blocked = unblocked_blocked and
        offender.spam_blocked = unblocked_blocked and
        offender.http_blocked = unblocked_blocked then
        put_line( "  unblocked" );
     elsif offender.sshd_blocked <= probation_blocked and
        offender.smtp_blocked <= probation_blocked and
        offender.spam_blocked <= probation_blocked and
        offender.http_blocked <= probation_blocked then
        put_line( "  probation" );
     else
        case offender.sshd_blocked is
        when unblocked_blocked =>
          put( "  SSHD unblocked" );
        when probation_blocked =>
          put( "  SSHD probation" );
        when short_blocked =>
          put( "  SSHD short blocked" );
        when banned_blocked =>
          put( "  SSHD banned" );
        when blacklisted_blocked =>
          put( "  SSHD blacklisted" );
        when others =>
          put( "  SSHD unknown" );
        end case;
        case offender.smtp_blocked is
        when unblocked_blocked =>
          put( "  SMTP unblocked" );
        when probation_blocked =>
          put( "  SMTP probation" );
        when short_blocked =>
          put( "  SMTP short blocked" );
        when banned_blocked =>
          put( "  SMTP banned" );
        when blacklisted_blocked =>
          put( "  SMTP blacklisted" );
        when others =>
          put( "  SMTP unknown" );
        end case;
        case offender.spam_blocked is
        when unblocked_blocked =>
          put( "  SPAM unblocked" );
        when probation_blocked =>
          put( "  SPAM probation" );
        when short_blocked =>
          put( "  SPAM short blocked" );
        when banned_blocked =>
          put( "  SPAM banned" );
        when blacklisted_blocked =>
          put( "  SPAM blacklisted" );
        when others =>
          put( "  SPAM unknown" );
        end case;
        case offender.http_blocked is
        when unblocked_blocked =>
          put( "  HTTP unblocked" );
        when probation_blocked =>
          put( "  HTTP probation" );
        when short_blocked =>
          put( "  HTTP short blocked" );
        when banned_blocked =>
          put( "  HTTP banned" );
        when blacklisted_blocked =>
          put( "  HTTP blacklisted" );
        when others =>
          put( "  HTTP unknown" );
        end case;
        new_line;
     end if;

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

