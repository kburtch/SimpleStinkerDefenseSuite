#!/usr/local/bin/spar

procedure export_blocked is
  pragma annotate( summary, "export_blocked" )
                @( description, "Write the details of blocked IP's in JSON " )
                @( description, "format to standard output." )
                @( author, "Ken O. Burtch" );
  pragma license( gplv3 );

  with separate "world.inc.sp";

  pragma restriction( no_external_commands );

  abt : btree_io.file( a_blocked_ip );
  abtc : btree_io.cursor( a_blocked_ip );
  key : string;
  source_ip : a_blocked_ip;
  j : json_string;
begin
  btree_io.open( abt, blocked_ip_path, blocked_ip_buffer_width, blocked_ip_buffer_width );
  btree_io.open_cursor( abt, abtc );
  btree_io.get_first( abt, abtc, key, source_ip );
  records.to_json( j, source_ip );
  put_line( j );
  loop
     btree_io.get_next( abt, abtc, key, source_ip );
     records.to_json( j, source_ip );
     put_line( j );
  end loop;
exception when others =>
  btree_io.close_cursor( abt, abtc );
  btree_io.close( abt );
end export_blocked;

-- vim: ft=spar

