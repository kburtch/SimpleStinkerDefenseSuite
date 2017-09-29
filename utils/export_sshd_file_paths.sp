#!/usr/local/bin/spar

procedure export_sshd_file_paths is
  pragma annotate( summary, "export_sshd_file_paths" )
                @( description, "Print the sshd violation files to " )
                @( description, "standard output." )
                @( author, "Ken O. Burtch" );
  pragma license( gplv3 );
  pragma software_model( shell_script );

  with separate "../config/contributors.inc.sp";
  with separate "../lib/world.inc.sp";
  with separate "../config/config.inc.sp";

  pragma restriction( no_external_commands );
begin
  put_line( sshd_violations_file_path );
end export_sshd_file_paths;

-- vim: ft=spar

