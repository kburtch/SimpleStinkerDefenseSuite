separate;

------------------------------------------------------------------------------
-- This file helper function to make blocking reports.
------------------------------------------------------------------------------

-----------------------------------------------------------------------------
-- Exported Subprograms
-----------------------------------------------------------------------------


procedure ip_report( the_offender : in out an_offender; the_country_name : string );
pragma assumption( used, ip_report );


-- IP REPORT
--
-- Produce a summary of an IP's activity.
-----------------------------------------------------------------------------

procedure ip_report( the_offender : in out an_offender; the_country_name : string ) is
begin
  put_line( the_offender.source_ip )
         @( "  DNS:           " & the_offender.source_name )
         @( "  Country:       " & the_country_name )
         @( "  Location:      " & the_offender.location );
  if the_offender.created_on /= "" then
     put_line( "  Tracked Since: " & get_date_string( the_offender.created_on ) );
  end if;
  if the_offender.logged_on /= "" then
     put_line( "  Last Event:    " & get_date_string( the_offender.logged_on ) );
  end if;
  if the_offender.updated_on /= "" then
     put_line( "  Last Updated:  " & get_date_string( the_offender.updated_on ) );
  end if;
  put_line( "  SSHD Events:  " & strings.image( the_offender.sshd_offences ) )
         @( "  SMTP Events:  " & strings.image( the_offender.mail_offences ) )
         @( "  SPAM Events:  " & strings.image( the_offender.spam_offences ) )
         @( "  HTTP Events:  " & strings.image( the_offender.http_offences ) )
         @( "  Grace:         " & strings.image( the_offender.grace ) )
         @( "  Sourced From:  " & the_offender.sourced_from );

  put( "  Data Type:     " );
  case the_offender.data_type is
  when real_data =>
    put_line( "real data" );
  when proxy_data =>
    put_line( "proxy data" );
  when test_data =>
    put_line( "test data" );
  when others =>
    put_line( "unknown" );
  end case;

  put( "  Status:      " );
  if the_offender.sshd_blocked = unblocked_blocked and
     the_offender.mail_blocked = unblocked_blocked and
     the_offender.spam_blocked = unblocked_blocked and
     the_offender.http_blocked = unblocked_blocked then
     put_line( "  unblocked" );
  elsif the_offender.sshd_blocked <= probation_blocked and
     the_offender.mail_blocked <= probation_blocked and
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
     case the_offender.mail_blocked is
     when unblocked_blocked =>
       put( "  Mail unblocked" );
     when probation_blocked =>
       put( "  Mail probation" );
     when short_blocked =>
       put( "  Mail short blocked" );
     when banned_blocked =>
       put( "  Mail banned" );
     when blacklisted_blocked =>
       put( "  Mail blacklisted" );
     when others =>
       put( "  Mail unknown" );
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

-- vim: ft=spar

