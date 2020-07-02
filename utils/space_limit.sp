with separate "config/contributors.inc.sp";
with separate "lib/world.inc.sp";
with separate "config/config.inc.sp";

procedure space_limit is

with separate "lib/alerts.inc.sp";

-- Because the error tests is written in Bash, this is a shim
-- to invoke the space limit alert on behalf of Bash.

begin
  startup_alerts;
  do_space_limit_alert;
  shutdown_alerts;
end space_limit;

-- vim: ft=spar

