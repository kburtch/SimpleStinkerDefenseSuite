#!/usr/local/bin/spar

procedure list_blocked is
  pragma annotate( summary, "list_blocked" )
                @( description, "Write a report blocked IP's to " )
                @( description, "standard output." )
                @( author, "Ken O. Burtch" );
  pragma license( gplv3 );

  with separate "world.inc.sp";

  pragma restriction( no_external_commands );

  abt : btree_io.file( a_blocked_ip );
  abtc : btree_io.cursor( a_blocked_ip );
  key : string;
  source_ip : a_blocked_ip;
  j : json_string;
begin
  btree_io.open( abt, blocked_ip_path, blocked_ip_buffer_width, blocked_ip_buffer_width );
  btree_io.open_cursor( abt, abtc );
  btree_io.get_first( abt, abtc, key, source_ip );
  loop
     put_line( source_ip.source_ip )
            @( "  DNS:        " & source_ip.source_name )
            @( "  Country:    " & source_ip.source_country )
            @( "  Location:   " & source_ip.location )
            @( "  SSHD:      " & strings.image( source_ip.sshd_offenses ) )
            @( "  SMTP:      " & strings.image( source_ip.smtp_offenses ) )
            @( "  HTTP:      " & strings.image( source_ip.http_offenses ) );
     case source_ip.sshd_blocked is
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

     -- source_ip       : ip_string;
     -- source_name     : dns_string;
     -- source_country  : country_string;
     -- location        : string;
     -- sshd_blocked    : blocking_status;
     -- sshd_blocked_on : timestamp_string;
     -- sshd_offenses   : natural;
     -- smtp_blocked    : blocking_status;
     -- smtp_blocked_on : timestamp_string;
     -- smtp_offenses   : natural;
     -- http_blocked    : blocking_status;
     -- http_blocked_on : timestamp_string;
     -- http_offenses   : natural;
     -- created_on      : timestamp_string;
     -- updated_on      : timestamp_string;

     btree_io.get_next( abt, abtc, key, source_ip );
  end loop;
exception when others =>
  btree_io.close_cursor( abt, abtc );
  btree_io.close( abt );
end list_blocked;

-- vim: ft=spar

