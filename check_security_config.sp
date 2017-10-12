#!/usr/local/bin/spar

with separate "config/contributors.inc.sp";
with separate "lib/world.inc.sp";
with separate "config/config.inc.sp";

procedure check_security_config is
  pragma annotate( summary, "check_security_config" )
                @( description, "Check the system's security configuration." )
                @( author, "Ken O. Burtch" );
  pragma license( gplv3 );
  pragma software_model( shell_script );

  i : integer;
  s : string;
  p : natural;
  security_issues : boolean := false;
begin
  -- Check the Linux iptables firewall

  i := integer( numerics.value( `iptables -L | wc -l ;` ) );
  if i <= 8 then
     security_issues;
     put_line( standard_error, source_info.source_location & " : " &
        "the Linux firewall is off" );
  end if;

  -- Check PermitRootLogin

  s := `cat /etc/ssh/sshd_config | fgrep PermitRootLogin ;`;
  p := strings.index( s, '#' );
  if p > 0 then
     s := strings.delete( s, p, strings.length( s ) );
  end if;
  p := strings.index( s, "true" );
  if s = "" or p > 0 then
     security_issues;
     put_line( standard_error, source_info.source_location & " : " &
        "PermitRootLogin is enabled or missing in sshd_config" );
  end if;

  -- Check PasswordAuthentication
  -- TODO: s may be multiple lines if some are comments

  s := `cat /etc/ssh/sshd_config | fgrep PasswordAuthentication ;`;
  p := strings.index( s, '#' );
  if p > 0 then
     s := strings.delete( s, p, strings.length( s ) );
  end if;
  p := strings.index( s, "yes" );
  if s = "" or p > 0 then
     security_issues;
     put_line( standard_error, source_info.source_location & " : " &
        "PasswordAuthentication enabled or missing in sshd_config" );
  end if;

  -- Check AllowUsers

  s := `cat /etc/ssh/sshd_config | fgrep AllowUsers ;`;
  p := strings.index( s, '#' );
  if p > 0 then
     s := strings.delete( s, p, strings.length( s ) );
  end if;
  if s = "" then
     security_issues;
     put_line( standard_error, source_info.source_location & " : " &
        "AllowUsers is missing in sshd_config" );
  end if;

  if security_issues then
     command_line.set_exit_status( 1 );
  else
     put_line( "OK" );
     command_line.set_exit_status( 0 );
  end if;
end check_security_config;

-- vim: ft=spar

