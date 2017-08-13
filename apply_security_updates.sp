#!/usr/local/bin/spar

procedure apply_security_updates is
  result : string;
  free_meg : natural := 0;
  cnt : natural;
begin
  cnt := 0;
  result := `yum list-security "--security" "--quiet";`;
  if $? /= 0 then
     put_line( "yum not working" );
  elsif result /= "" then
     cnt := numerics.value( `echo "$result" | wc -l;` );
  end if;
  ? strings.image( cnt ) & " security updates available";
  if cnt > 0 then
     null; -- /bin/yum "--quiet" "--security" "--assumeyes" update
  end if;

-- certbot renew

  -- Anti-virus scan

-- clamscan -r -i --no-summary /home
  free_meg := numerics.value( `free -m | fgrep Mem: | tr -s ' ' | cut -d' ' -f4;` );
  result := `nice find /home/ -type f -size "-""$free_meg""M" -exec clamscan -i "--no-summary" {} \; ;`;
  ? result;

end apply_security_updates;

-- vim: ft=spar

