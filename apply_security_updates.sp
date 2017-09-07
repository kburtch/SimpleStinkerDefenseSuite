#!/usr/local/bin/spar

procedure apply_security_updates is

pragma annotate( summary, "apply_security_updates" )
              @( description, "Process a sshd log file (violations file) and block " )
              @( description, "suspicious IP numbers.  By default, the violations " )
              @( description, "file is /var/log/secure." )
              --@( errors, " - " )
              @( author, "Ken O. Burtch" );
pragma license( gplv3 );
pragma software_model( shell_script );

with separate "config/contributors.inc.sp";
with separate "lib/world.inc.sp";
with separate "config/config.inc.sp";

  result : string;
  summary_line : string;
  free_meg : natural := 0;
  cnt : natural;
begin
  cnt := 0;
  result := `yum "--security" "--assumeno" | tail -2 | head -1;`;
  summary_line := `echo "$result" | tail -2 | head -1;`;
  if $? /= 0 then
     put_line( "yum not working" );
  elsif strings.index( summary_line, "No packages needed for security" ) = 0 then
     log_info( source_info.source_location ) @ ( "No security updates" );
  else
     -- TODO this is wrong
     cnt := numerics.value( `echo "$result" | wc -l;` );
     ? strings.image( cnt ) & " security updates available";
     if cnt > 0 then
        null; -- /bin/yum "--quiet" "--security" "--assumeyes" update
     end if;
  end if;

-- certbot renew

  -- Anti-virus scan

-- clamscan -r -i --no-summary /home
  free_meg := numerics.value( `free -m | fgrep Mem: | tr -s ' ' | cut -d' ' -f4;` );
  result := `nice find /home/ -type f -size "-""$free_meg""M" -exec clamscan -i "--no-summary" {} \; ;`;
  ? result;

end apply_security_updates;

-- vim: ft=spar

