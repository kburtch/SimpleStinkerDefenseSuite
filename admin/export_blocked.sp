#!/usr/local/bin/spar

with separate "config/contributors.inc.sp";
with separate "lib/world.inc.sp";
with separate "config/config.inc.sp";

procedure export_blocked is
  pragma annotate( summary, "export_blocked" )
                @( description, "Save the offender database as JSON to standard output." )
                @( description, "This can be used to back or restore the database." )
                @( author, "Ken O. Burtch" );
  pragma license( gplv3 );
  pragma software_model( shell_script );

  with separate "lib/common.inc.sp";
  with separate "lib/blocking.inc.sp";

  pragma restriction( no_external_commands );

  offender_cursor : btree_io.cursor( an_offender );
  offender_key : string;
  offender : an_offender;
  offender_json : json_string;
begin
  btree_io.open( offender_file, string( offender_path ), offender_buffer_width, offender_buffer_width );
  btree_io.open_cursor( offender_file, offender_cursor );
  btree_io.get_first( offender_file, offender_cursor, offender_key, offender );
  loop
     records.to_json( offender_json, offender );
     put_line( offender_json );
     btree_io.get_next( offender_file, offender_cursor, offender_key, offender );
  end loop;
exception when others =>
  if btree_io.is_open( offender_file ) then
     btree_io.close_cursor( offender_file, offender_cursor );
     btree_io.close( offender_file );
  end if;
end export_blocked;

-- vim: ft=spar

