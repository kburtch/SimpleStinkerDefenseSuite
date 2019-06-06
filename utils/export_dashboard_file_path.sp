#!/usr/local/bin/spar

with separate "../config/contributors.inc.sp";
with separate "../lib/world.inc.sp";
with separate "../config/config.inc.sp";

procedure export_dashboard_file_path is
  pragma annotate( summary, "export_dashboard_file_path" )
                @( description, "Print the location of the web dashboard " )
                @( description, "standard output." )
                @( author, "Ken O. Burtch" );
  pragma license( gplv3 );
  pragma software_model( shell_script );

  pragma restriction( no_external_commands );
begin
  put_line( dashboard_path );
end export_dashboard_file_path;

-- vim: ft=spar

