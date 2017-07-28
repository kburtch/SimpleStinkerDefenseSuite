#!/usr/local/bin/spar

procedure export_blocked is
  pragma annotate( summary, "export_blocked" )
                @( description, "Write the details of blocked IP's in JSON " )
                @( description, "format to standard output." )
                @( author, "Ken O. Burtch" );
  pragma license( gplv3 );
  pragma software_model( shell_script );

  with separate "config/contributors.inc.sp";
  with separate "lib/world.inc.sp";
  with separate "config/config.inc.sp";
  with separate "lib/common.inc.sp";
  with separate "lib/blocking.inc.sp";

  pragma restriction( no_external_commands );

  offender_cursor : btree_io.cursor( an_offender );
  offender_key : string;
  offender : an_offender;
  j : json_string;
begin
  btree_io.open( offender_file, offender_path, offender_buffer_width, offender_buffer_width );
  btree_io.open_cursor( offender_file, offender_cursor );
  btree_io.get_first( offender_file, offender_cursor, offender_key, offender );
  records.to_json( j, offender );
  put_line( j );
  loop
     btree_io.get_next( offender_file, offender_cursor, offender_key, offender );
     records.to_json( j, offender );
     put_line( j );
  end loop;
exception when others =>
  if btree_io.is_open( offender_file ) then
     btree_io.close_cursor( offender_file, offender_cursor );
     btree_io.close( offender_file );
  end if;
end export_blocked;

-- vim: ft=spar

