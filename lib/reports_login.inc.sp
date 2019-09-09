separate;

------------------------------------------------------------------------------
-- This file contains helper function to create login reports.
------------------------------------------------------------------------------

-----------------------------------------------------------------------------
-- Exported Subprograms
-----------------------------------------------------------------------------


procedure login_report( login : in out a_sshd_login );


-- LOGIN REPORT
--
-- Produce a report on a login's use.
-----------------------------------------------------------------------------

procedure login_report( login : in out a_sshd_login ) is
begin
  put_line( login.username );
  put( "  Count:        " ) @ ( login.count  ); new_line;
  put( "  Kind:          " ) @ ( login.kind   ); new_line;
  put( "  Existence:     " ) @ ( login.existence ); new_line;
  if login.created_on /= "" then
     put_line( "  Tracked Since: " & get_date_string( login.created_on ) );
  end if;
  if login.logged_on /= "" then
     put_line( "  Last Event:    " & get_date_string( login.logged_on ) );
  end if;
  if login.updated_on /= "" then
     put_line( "  Last Updated:  " & get_date_string( login.updated_on ) );
  end if;
  put( "  Comment:       " ) @ ( login.comment ); new_line;
  new_line;
end login_report;

--  case the_offender.data_type is
--  when real_data =>
--    put_line( "real data" );
--  when proxy_data =>
--    put_line( "proxy data" );
--  when test_data =>
--    put_line( "test data" );
--  when others =>
--    put_line( "unknown" );
--  end case;
pragma assumption( used, login_report );

-- vim: ft=spar

