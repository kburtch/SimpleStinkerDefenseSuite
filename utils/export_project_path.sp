#!/usr/local/bin/spar

with separate "../config/contributors.inc.sp";
with separate "../lib/world.inc.sp";
with separate "../config/config.inc.sp";

procedure export_project_path is
  pragma annotate( summary, "export_project_path" )
                @( description, "Print the ssds project path to " )
                @( description, "standard output." )
                @( author, "Ken O. Burtch" );
  pragma license( gplv3 );
  pragma software_model( shell_script );

  pragma restriction( no_external_commands );
begin
  put_line( project_path );
end export_project_path;

-- vim: ft=spar

