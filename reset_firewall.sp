with separate "config/contributors.inc.sp";
with separate "lib/world.inc.sp";
with separate "config/config.inc.sp";

procedure reset_firewall is

with separate "lib/common.inc.sp";
with separate "lib/blocking.inc.sp";

  -- TODO: to do a full reset, ipset blockset must be deleted first.

  reply : string;
begin
  setupWorld( "reset_firewall", "log/blocker.log" );
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

