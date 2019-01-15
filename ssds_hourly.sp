with separate "config/contributors.inc.sp";
with separate "lib/world.inc.sp";
with separate "config/config.inc.sp";

procedure ssds_hourly is
  pragma annotate( summary, "ssds_hourly" )
                @( description, "Run SSDS hourly tasks." )
                @( author, "Ken O. Burtch" );
  pragma license( gplv3 );
  pragma software_model( shell_script );
  spar : limited command := "/usr/local/bin/spar";
begin
  spar admin/import_bsdly.sp -D;
  spar wash_blocked.sp -D;
end ssds_hourly;

-- vim: ft=spar

