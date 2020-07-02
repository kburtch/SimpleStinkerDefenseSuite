with separate "config/contributors.inc.sp";
with separate "lib/world.inc.sp";
with separate "config/config.inc.sp";

procedure export_spam_limit is
  pragma annotate( summary, "export_spam_limi" )
                @( description, "Print the spam alert limit to " )
                @( description, "standard output." )
                @( author, "Ken O. Burtch" );
  pragma license( gplv3 );
  pragma software_model( shell_script );

  pragma restriction( no_external_commands );

-- Because the alert test is written in Bash, this is a shim
-- to return the limit on behalf of Bash.

begin
  put_line( alert_thresholds( spam_limit_alert ) );
end export_spam_limit;

-- vim: ft=spar

