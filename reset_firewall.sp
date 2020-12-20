with separate "config/contributors.inc.sp";
with separate "lib/world.inc.sp";
with separate "config/config.inc.sp";

procedure reset_firewall is

with separate "lib/common.inc.sp";
with separate "lib/blocking.inc.sp";

  reply : string;
  tmp : string;
begin
  setupWorld( "log/blocker.log", log_mode.echo );
  put_line( "Resetting the firewall will set up the default firewall" );
  put_line( "rules." );
  new_line;
  -- Red Hat Linux firewall should be stopped
  tmp := `ps -ef | fgrep "firewall.d" | wc -l;`;
  if tmp /= "1" then
     put_line( "firewall.d is running.  stop this service first" );
     command_line.set_exit_status( 192 );
     return;
  end if;
  -- Our firewall should be stopped also
  tmp := `ps -ef;`;
  tmp := `echo "$tmp" | fgrep "sshd_blocker" | wc -l;`;
  if tmp = "1" then
     put_line( "the firewall is running.  stop this first" );
     command_line.set_exit_status( 192 );
     return;
  end if;
  -- Confirm to proceed
  put_line( "Reset the firewall? (Y/N)" );
  reply := get_line;
  if reply = "y" then
     ipset list -terse blocklist > "/dev/null";
     if $? = 0 then
        put_line( "Clear all currently blocked IP numbers? (Y/N)" );
        reply := get_line;
        if reply = "y" then
           ipset destroy blocklist;
        else
           put_line( "Not cleared." );
        end if;
     else
        put_line( "Note: ipset not currently set up.  It will be on reset." );
     end if;
     reset_firewall_to_defaults;
     if files.exists( "admin/import_offenders.sp" ) then
        put_line( "Import data from last backup? (Y/N)" );
        reply := get_line;
        if reply = "y" then
           put_line( "Have you erased the data directory? (Y/N)" );
           reply := get_line;
           if reply = "y" then
              put_line( "Creating country list" );
              cd setup;
              spar init_countries.sp;
              cd ..;
              put_line( "Creating HTTP attack vectors list" );
              cd setup;
              spar -C init_http_vectors.sp;
              cd .. ;
              put_line( "Importing blocked ip list" );
              gzip -c -d backups/offenders.gz | spar admin/import_offenders.sp ;
              put_line( "Importing logins list" );
              gzip -c -d backups/logins.gz | admin/import_logins.sp ;
           else
              put_line( "Skipping import" );
           end if;
        else
           put_line( "Skipping import" );
        end if;
     else
        put_line( "Note: no backups exist...skipping recovery from backups" );
     end if;
  else
     put_line( "Cancelled" );
  end if;
  shutdownWorld;
end reset_firewall;

-- vim: ft=spar

