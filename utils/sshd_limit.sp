with separate "config/contributors.inc.sp";
with separate "lib/world.inc.sp";
with separate "config/config.inc.sp";

procedure sshd_limit is

with separate "lib/common.inc.sp";
with separate "lib/alerts.inc.sp";

-- Because the error tests is written in Bash, this is a shim
-- to invoke the error limit alert on behalf of Bash.

begin
  setupWorld( "log/blocker.log", log_mode.file );
  startup_alerts;
  do_sshd_limit_alert;
  shutdown_alerts;
  shutdownWorld;
end sshd_limit;

-- vim: ft=spar

