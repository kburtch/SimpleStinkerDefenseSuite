#!/usr/local/bin/spar

procedure export_http_file_paths is
  pragma annotate( summary, "export_http_file_paths" )
                @( description, "Print the http violation files to " )
                @( description, "standard output." )
                @( author, "Ken O. Burtch" );
  pragma license( gplv3 );
  pragma software_model( shell_script );

  with separate "../config/contributors.inc.sp";
  with separate "../lib/world.inc.sp";
  with separate "../config/config.inc.sp";

  pragma restriction( no_external_commands );
begin
  for i in arrays.first( http_violations_file_paths )..arrays.last( http_violations_file_paths ) loop
      put_line( http_violations_file_paths( i ) );
  end loop;
end export_http_file_paths;

-- vim: ft=spar

