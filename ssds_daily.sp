#!/usr/local/bin/spar

with separate "config/contributors.inc.sp";
with separate "lib/world.inc.sp";
with separate "config/config.inc.sp";

procedure ssds_daily is

   with separate "lib/common.inc.sp";
   with separate "lib/alerts.inc.sp";

   pragma annotate( summary, "ssds_daily" )
                 @( description, "Run daily tasks" )
                 @( author, "Ken O. Burtch" );
   pragma license( gplv3 );
   pragma software_model( shell_script );

   bash : limited command := "/bin/bash";
   mail : limited command := "/bin/mail";
   spar : limited command := "/usr/local/bin/spar";

   TMP : string;
begin
  setupWorld( "log/blocker.log", log_mode.file );
  startup_alerts;
  reset_alerts;

  TMP := "/tmp/daily_report." & strings.trim( strings.image( $$ ) );

  cd /root/ssds;

  bash "report_daily.sh" 2>&1 > "$TMP";
  if report_email /= "" then
     mail -s "SSDS Daily Report: $HOSTNAME" "$report_email" < "$TMP";
  end if;
  rm "$TMP";

  -- Backup database
  spar -m "nightly_backup.sp";

  shutdown_alerts;
  shutdownWorld;
end ssds_daily;

-- vim: ft=spar

