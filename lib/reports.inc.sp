separate;

procedure ip_report( the_offender : in out an_offender; the_country_name : string ) is
begin
  put_line( the_offender.source_ip )
         @( "  DNS:       " & the_offender.source_name )
         @( "  Country:   " & the_country_name )
         @( "  Location:  " & the_offender.location )
         @( "  Tracked:   " & the_offender.created_on )
         @( "  Last Seen: " & the_offender.logged_on )
         @( "  SSHD:     " & strings.image( the_offender.sshd_offenses ) )
         @( "  SMTP:     " & strings.image( the_offender.smtp_offenses ) )
         @( "  SPAM:     " & strings.image( the_offender.spam_offenses ) )
         @( "  HTTP:     " & strings.image( the_offender.http_offenses ) );
  put( "  Status:   " );
  if the_offender.sshd_blocked = unblocked_blocked and
     the_offender.smtp_blocked = unblocked_blocked and
     the_offender.spam_blocked = unblocked_blocked and
     the_offender.http_blocked = unblocked_blocked then
     put_line( "  unblocked" );
  elsif the_offender.sshd_blocked <= probation_blocked and
     the_offender.smtp_blocked <= probation_blocked and
     the_offender.spam_blocked <= probation_blocked and
     the_offender.http_blocked <= probation_blocked then
     put_line( "  probation" );
  else
     case the_offender.sshd_blocked is
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
     case the_offender.smtp_blocked is
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
     case the_offender.spam_blocked is
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
     case the_offender.http_blocked is
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
end ip_report;
pragma assumption( used, ip_report );

-- vim: ft=spar

