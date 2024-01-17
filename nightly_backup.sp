procedure nightly_backup is
  pragma annotate( summary, "nightly_backup" )
                @( description, "Backup the logins and offenders databases." )
                @( author, "Ken O. Burtch" );
  pragma license( gplv3 );
  pragma software_model( shell_script );

  spar   : limited command := "/usr/local/bin/spar";

  type import_string is new string;

  LOGNAME : constant import_string := "";
  pragma import( shell, LOGNAME );

  type file_path is new string;
  lock_file : constant file_path := "lock/backup.lck";

  status : natural;
begin
  -- sanity tests

  if LOGNAME /= "root" then
     put_line( standard_error, source_info.source_location & ": this must run as the superuser" );
     command_line.set_exit_status(1);
     return;
  end if;
  if not files.exists( "backups" ) then
     put_line( standard_error, source_info.source_location & ": the backups directory does not exist" );
     command_line.set_exit_status(1);
     return;
  end if;
  if files.exists( string( lock_file ) ) then
     put_line( standard_error, source_info.source_location & ": a lock file exists...is backup already running?" );
     command_line.set_exit_status(2);
     return;
  end if;

  -- create simple lock file

  touch "$lock_file";

  -- backup the databases into temp files

  spar "admin/export_logins.sp" | gzip > "backups/logins.tmp.gz";
  status := $?;
  spar "admin/export_offenders.sp" | gzip > "backups/offenders.tmp.gz";
  status := numerics.max( @, $? );

  -- if nothing went wrong, then save the backups
  -- otherwise, erase the temp files as failures.

  if status = 0 then
     mv "backups/logins.tmp.gz" "backups/logins.gz";
     mv "backups/offenders.tmp.gz" "backups/offenders.gz";
  else
     if files.exists( "backups/login.tmp.gz" ) then
        rm backups/login.tmp.gz;
     end if;
     if files.exists( "backups/offenders.tmp.gz" ) then
        rm backups/offenders.tmp.gz;
     end if;
     put_line( standard_error, source_info.source_location & ": backup failed" );
  end if;

  -- remove simple lock file

  rm "$lock_file";
exception when others =>
  put_line( standard_error, exceptions.exception_info );
  rm "$lock_file";
end nightly_backup;

-- vim: set ft=spar

