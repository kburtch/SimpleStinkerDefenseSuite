separate;

------------------------------------------------------------------------------
-- This file contains definitions for geolocation
------------------------------------------------------------------------------

alert_history_path : constant file_path:= "data/alert_history.txt";

type an_alert_history is array(error_limit_alert..spam_limit_alert) of integer;
alert_history : an_alert_history;

-----------------------------------------------------------------------------
-- Exported Subprograms
-----------------------------------------------------------------------------

procedure do_error_limit_alert;
pragma assumption( used, do_error_limit_alert );

procedure do_space_limit_alert;
pragma assumption( used, do_space_limit_alert );

procedure do_blocks_limit_alert;
pragma assumption( used, do_blocks_limit_alert );

procedure do_http_limit_alert;
pragma assumption( used, do_http_limit_alert );

procedure do_mail_limit_alert;
pragma assumption( used, do_mail_limit_alert );

procedure do_sshd_limit_alert;
pragma assumption( used, do_sshd_limit_alert );

procedure do_spam_limit_alert;
pragma assumption( used, do_spam_limit_alert );

procedure reset_alerts;
pragma assumption( used, reset_alerts );

procedure startup_alerts;

procedure shutdown_alerts;


-- SEND MAIL

procedure send_mail( subject : string; msg : string ) is
  TMP : string;
begin
  TMP := "/tmp/alert." & strings.trim( strings.image( $$ ) );
  echo "$msg" > "$TMP";
  mail -s "$subject" "$alert_email" < "$TMP";
  rm "$TMP";
end send_mail;


-- do error limit alert

procedure do_error_limit_alert is
   action : constant alert_action := alert_actions( error_limit_alert );
begin
   return when alert_history( error_limit_alert ) = 1;

   case action is
   when block_action =>
      null;
   when email_action =>
      send_mail( "SSDS Error Limit exceeded: " & string( HOSTNAME ),
                 "More than" &
                 strings.image( alert_thresholds( error_limit_alert ) ) &
                 "  errors occurred" );
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
   action : constant alert_action := alert_actions( space_limit_alert );
begin
   return when alert_history( space_limit_alert ) = 1;

   case action is
   when block_action =>
      null;
   when email_action =>
      send_mail( "SSDS Space Limit exceeded: " & string( HOSTNAME ),
                 "More than" &
                 strings.image( alert_thresholds( space_limit_alert ) ) &
                 "  M space used" );
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
   action : constant alert_action := alert_actions( blocks_limit_alert );
begin
   return when alert_history( blocks_limit_alert ) = 1;

   case action is
   when block_action =>
      null;
   when email_action =>
      send_mail( "SSDS Blocks Limit exceeded: " & string( HOSTNAME ),
                 "More than" &
                 strings.image( alert_thresholds( blocks_limit_alert ) ) &
                 "  IP blocks occurred" );
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

procedure do_http_limit_alert is
   action : constant alert_action := alert_actions( http_limit_alert );
begin
   return when alert_history( http_limit_alert ) = 1;

   case action is
   when block_action =>
      null;
   when email_action =>
      send_mail( "SSDS Web Threat Limit exceeded: " & string( HOSTNAME ),
                 "More than" &
                 strings.image( alert_thresholds( http_limit_alert ) ) &
                 "  HTTP threats occurred" );
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

procedure do_mail_limit_alert is
   action : constant alert_action := alert_actions( mail_limit_alert );
begin
   return when alert_history( mail_limit_alert ) = 1;

   case action is
   when block_action =>
      null;
   when email_action =>
      send_mail( "SSDS Mail Limit exceeded: " & string( HOSTNAME ),
                 "More than" &
                 strings.image( alert_thresholds( mail_limit_alert ) ) &
                 "  mail login threats occurred" );
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

procedure do_sshd_limit_alert is
   action : constant alert_action := alert_actions( sshd_limit_alert );
begin
   return when alert_history( sshd_limit_alert ) = 1;

   case action is
   when block_action =>
      null;
   when email_action =>
      send_mail( "SSDS Login Limit exceeded: " & string( HOSTNAME ),
                 "More than" &
                 strings.image( alert_thresholds( sshd_limit_alert ) ) &
                 "  SSH login threats occurred" );
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

procedure do_spam_limit_alert is
   action : constant alert_action := alert_actions( spam_limit_alert );
begin
   return when alert_history( spam_limit_alert ) = 1;

   case action is
   when block_action =>
      null;
   when email_action =>
      send_mail( "SSDS Spam Limit exceeded: " & string( HOSTNAME ),
                 "More than" &
                 strings.image( alert_thresholds( spam_limit_alert ) ) &
                 "  spam events occurred" );
   when evade_action =>
      logs.warning( "Evade not yet implemented" );
   when shutdown_action =>
      logs.warning( "Shutdown not yet implemented" );
   when others =>
      logs.error( "Alert action is unknown" );
   end case;

   alert_history( spam_limit_alert ) := 1;
end do_spam_limit_alert;


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

