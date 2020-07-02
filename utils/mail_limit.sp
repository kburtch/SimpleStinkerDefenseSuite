with separate "config/contributors.inc.sp";
with separate "lib/world.inc.sp";
with separate "config/config.inc.sp";

procedure mail_limit is

with separate "lib/alerts.inc.sp";

-- Because the error tests is written in Bash, this is a shim
-- to invoke the error limit alert on behalf of Bash.

begin
  startup_alerts;
  do_mail_limit_alert;
  shutdown_alerts;
end mail_limit;

-- vim: ft=spar

