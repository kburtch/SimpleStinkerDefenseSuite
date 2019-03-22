#!/usr/local/bin/spar

procedure ssds_daily is
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
  TMP := "/tmp/daily_report." & strings.trim( strings.image( $$ ) );

  cd /root/ssds;

  bash "daily_report.sh" 2>&1 > "$TMP";
  mail -s "SSDS Daily Report" "ken@pegasoft.ca" < "$TMP";
  rm "$TMP";

  -- Backup database
  spar -m "nightly_backup.sp";

end ssds_daily;

-- vim: ft=spar

