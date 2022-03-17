separate;

------------------------------------------------------------------------------
-- This file remembers if an alert has been recently sent to avoid excessive
-- messages.
------------------------------------------------------------------------------

alert_history_path : constant file_path:= "data/alert_history.txt";

type an_alert_history is array(error_limit_alert..outgoing_email_limit_alert) of integer;
alert_history : an_alert_history;

------------------------------------------------------------------------------
-- This file records alerts for later review.
------------------------------------------------------------------------------

alert_log_path : constant file_path:= "log/alert.log";

-----------------------------------------------------------------------------
-- Exported Subprograms
-----------------------------------------------------------------------------

procedure do_error_limit_alert;
pragma assumption( used, do_error_limit_alert );

procedure do_space_limit_alert;
pragma assumption( used, do_space_limit_alert );

procedure do_blocks_limit_alert;
pragma assumption( used, do_blocks_limit_alert );

procedure do_http_limit_alert( actual : natural );
pragma assumption( used, do_http_limit_alert );

procedure do_mail_limit_alert( actual : natural );
pragma assumption( used, do_mail_limit_alert );

procedure do_sshd_limit_alert( actual : natural );
pragma assumption( used, do_sshd_limit_alert );

procedure do_spam_limit_alert( actual : natural );
pragma assumption( used, do_spam_limit_alert );

procedure do_outgoing_email_limit_alert( account : string; actual : natural );
pragma assumption( used, do_outgoing_email_limit_alert );

procedure reset_alerts;
pragma assumption( used, reset_alerts );

procedure startup_alerts;

procedure shutdown_alerts;


-- LOG ALERT
--
-- Simple procedure to write the alert message to a file.

procedure log_alert( msg : string ) is
  log : file_type;
begin
  if files.exists( string( alert_log_path ) ) then
     open( log, append_file, alert_log_path );
  else
     create( log, out_file, alert_log_path );
  end if;
  -- TODO: not the best time stamp
  put( log, `date` );
  put( log, ":" );
  put_line( log, msg );
  close( log );
end log_alert;


-- SEND MAIL
--
-- Send an email, logging the alert in the main log and in the alert log.

procedure send_mail( subject : string; msg : string ) is
  TMP : string;
begin
  logs.warning( "Alert: " & subject );
  log_alert( msg );
  TMP := "/tmp/alert." & strings.trim( strings.image( $$ ) );
  echo "$msg" > "$TMP";
  mail -s "$subject" "$alert_email" < "$TMP";
  rm "$TMP";
end send_mail;


-- do error limit alert

procedure do_error_limit_alert is
   action : limited alert_action := alert_actions( error_limit_alert );
begin
   return when alert_history( error_limit_alert ) = 1;

   case action is
   when block_action =>
      null;
   when email_action =>
      send_mail( "SSDS Error Limit exceeded: " & string( HOSTNAME ),
                 strings.image( alert_thresholds( error_limit_alert ) ) &
                 " or more errors occurred" );
   when evade_action =>
      logs.warning( "Evade not yet implemented" );
   when shutdown_action =>
      logs.warning( "Shutdown not yet implemented" );
   when others =>
      logs.error( "Alert action is unknown" );
   end case;

   alert_history( error_limit_alert ) := 1;
end do_error_limit_alert;


-- do space limit alert

procedure do_space_limit_alert is
   action : limited alert_action := alert_actions( space_limit_alert );
begin
   return when alert_history( space_limit_alert ) = 1;

   case action is
   when block_action =>
      null;
   when email_action =>
      send_mail( "SSDS Space Limit exceeded: " & string( HOSTNAME ),
                 strings.image( alert_thresholds( space_limit_alert ) ) &
                 " M or more space used" );
   when evade_action =>
      logs.warning( "Evade not yet implemented" );
   when shutdown_action =>
      logs.warning( "Shutdown not yet implemented" );
   when others =>
      logs.error( "Alert action is unknown" );
   end case;

   alert_history( space_limit_alert ) := 1;
end do_space_limit_alert;


-- do blocks limit alert

procedure do_blocks_limit_alert is
   action : limited alert_action := alert_actions( blocks_limit_alert );
begin
   return when alert_history( blocks_limit_alert ) = 1;

   case action is
   when block_action =>
      null;
   when email_action =>
      send_mail( "SSDS Blocks Limit exceeded: " & string( HOSTNAME ),
                 strings.image( alert_thresholds( blocks_limit_alert ) ) &
                 " or more IP blocks occurred" );
   when evade_action =>
      logs.warning( "Evade not yet implemented" );
   when shutdown_action =>
      logs.warning( "Shutdown not yet implemented" );
   when others =>
      logs.error( "Alert action is unknown" );
   end case;

   alert_history( blocks_limit_alert ) := 1;
end do_blocks_limit_alert;


-- do http limit alert

procedure do_http_limit_alert( actual : natural ) is
   action : limited alert_action := alert_actions( http_limit_alert );
begin
   return when alert_history( http_limit_alert ) = 1;

   case action is
   when block_action =>
      null;
   when email_action =>
      send_mail( "SSDS Web Threat Limit exceeded: " & string( HOSTNAME ),
                 strings.image( actual ) &
                 " HTTP threats occurred (" &
                 strings.image( alert_thresholds( http_limit_alert ) ) & " or more )");
   when evade_action =>
      logs.warning( "Evade not yet implemented" );
   when shutdown_action =>
      logs.warning( "Shutdown not yet implemented" );
   when others =>
      logs.error( "Alert action is unknown" );
   end case;

   alert_history( http_limit_alert ) := 1;
end do_http_limit_alert;


-- do mail limit alert

procedure do_mail_limit_alert( actual : natural ) is
   action : limited alert_action := alert_actions( mail_limit_alert );
begin
   return when alert_history( mail_limit_alert ) = 1;

   case action is
   when block_action =>
      null;
   when email_action =>
      send_mail( "SSDS Mail Limit exceeded: " & string( HOSTNAME ),
                 strings.image( actual ) &
                 " mail login threats occurred (" &
                 strings.image( alert_thresholds( mail_limit_alert ) ) & " or more)" );
   when evade_action =>
      logs.warning( "Evade not yet implemented" );
   when shutdown_action =>
      logs.warning( "Shutdown not yet implemented" );
   when others =>
      logs.error( "Alert action is unknown" );
   end case;

   alert_history( mail_limit_alert ) := 1;
end do_mail_limit_alert;


-- do sshd limit alert

procedure do_sshd_limit_alert( actual : natural ) is
   action : limited alert_action := alert_actions( sshd_limit_alert );
begin
   return when alert_history( sshd_limit_alert ) = 1;

   case action is
   when block_action =>
      null;
   when email_action =>
      send_mail( "SSDS Login Limit exceeded: " & string( HOSTNAME ),
                 strings.image( actual ) &
                 " SSH login threats occurred (" &
                 strings.image( alert_thresholds( sshd_limit_alert ) ) & " or more)" );
   when evade_action =>
      logs.warning( "Evade not yet implemented" );
   when shutdown_action =>
      logs.warning( "Shutdown not yet implemented" );
   when others =>
      logs.error( "Alert action is unknown" );
   end case;

   alert_history( sshd_limit_alert ) := 1;
end do_sshd_limit_alert;


-- do spam limit alert

procedure do_spam_limit_alert( actual : natural ) is
   action : limited alert_action := alert_actions( spam_limit_alert );
begin
   log.warning( alert_history( spam_limit_alert ) ); -- DEBUG
   return when alert_history( spam_limit_alert ) = 1;

   case action is
   when block_action =>
      log.warning( "block action" ); -- DEBUG
      null;
   when email_action =>
      send_mail( "SSDS Spam Limit exceeded: " & string( HOSTNAME ),
                 strings.image( actual ) &
                 " spam events occurred (" &
                 strings.image( alert_thresholds( spam_limit_alert ) ) & " or more)" );
   when evade_action =>
      logs.warning( "Evade not yet implemented" );
   when shutdown_action =>
      logs.warning( "Shutdown not yet implemented" );
   when others =>
      logs.error( "Alert action is unknown" );
   end case;

   alert_history( spam_limit_alert ) := 1;
end do_spam_limit_alert;


-- do outgoing email limit alert

procedure do_outgoing_email_limit_alert( account : string; actual : natural ) is
   action : limited alert_action := alert_actions( outgoing_email_limit_alert );
begin
   return when alert_history( outgoing_email_limit_alert ) = 1;

   case action is
   when block_action =>
      null;
   when email_action =>
      send_mail( "SSDS Outgoing Limit exceeded: " & string( HOSTNAME ),
                 strings.image( actual ) &
                 " outgoing emails occurred " &
                 "from " & strings.to_escaped( account ) & " (" &
                 strings.image( alert_thresholds( outgoing_email_limit_alert ) ) & " or more)" );
   when evade_action =>
      logs.warning( "Evade not yet implemented" );
   when shutdown_action =>
      logs.warning( "Shutdown not yet implemented" );
   when others =>
      logs.error( "Alert action is unknown" );
   end case;

   alert_history( outgoing_email_limit_alert ) := 1;
end do_outgoing_email_limit_alert;


-- Treat all alerts as unsent

procedure reset_alerts is
begin
   for i in enums.first(alert_kinds)..enums.last(alert_kinds) loop
       alert_history(i) := 0;
   end loop;
end reset_alerts;


-- Read the alert history

procedure startup_alerts is
   alert_history_file : file_type;
begin
   -- Assume the alerts were not sent
   reset_alerts;
   -- Read the alert history
   if files.exists( string( alert_history_path ) ) then
      open( alert_history_file, in_file, string( alert_history_path ) );
      for i in enums.first(alert_kinds)..enums.last(alert_kinds) loop
          alert_history(i) := numerics.value( get_line( alert_history_file ) );
          exit when end_of_file( alert_history_file );
      end loop;
      close( alert_history_file );
   end if;
end startup_alerts;


-- Save the alert history

procedure shutdown_alerts is
   alert_history_file : file_type;
begin
   create( alert_history_file, out_file, string( alert_history_path ) );
   for i in enums.first(alert_kinds)..enums.last(alert_kinds) loop
       put_line( alert_history_file, strings.image( alert_history( i ) ) );
   end loop;
   close( alert_history_file );
end shutdown_alerts;

-- vim: ft=spar

