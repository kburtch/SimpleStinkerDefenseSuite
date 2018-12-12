with separate "config/contributors.inc.sp";
with separate "lib/world.inc.sp";
with separate "config/config.inc.sp";

procedure reset_firewall is

with separate "lib/logging.inc.sp";
with separate "lib/common.inc.sp";
with separate "lib/blocking.inc.sp";

  reply : string;
  tmp : string;
begin
  setupWorld( "log/blocker.log", log_mode.echo );
  put_line( "TODO: to do a full reset, ipset blockset must be deleted first." );
  tmp := `ps -ef | fgrep "firewall.d" | wc -l;`;
  if tmp /= "1" then
     put_line( "firewall.d is running.  stop this first" );
     command_line.set_exit_status( 192 );
     return;
  end if;
  put_line( "Reset firewall? (Y/N)" );
  reply := get_line;
  if reply = "y" then
     reset_firewall;
  else
     put_line( "Cancelled" );
  end if;
  shutdownWorld;
end reset_firewall;

-- vim: ft=spar

