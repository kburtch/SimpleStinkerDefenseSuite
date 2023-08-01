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
  hourly_lock : constant string := "lock/hourly.lck";
begin
  -- It is possible that the hourly tasks take longer than 1 hour to run.
  -- Do not start a second round if a previous one is in progress.
  if not files.exists( hourly_lock ) then
     touch( hourly_lock );

     spar admin/import_bsdly.sp -D;
     spar wash_blocked.sp -D;
     bash report_hourly.sh;

     if files.exists( hourly_lock ) then
        rm( hourly_lock );
     end if;
  end if;
end ssds_hourly;

-- vim: ft=spar

