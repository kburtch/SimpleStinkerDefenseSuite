#!/usr/local/bin/spar

with separate "../config/contributors.inc.sp";
with separate "../lib/world.inc.sp";
with separate "../config/config.inc.sp";

procedure init_http_vectors is

pragma annotate( summary, "init_countries" )
              @( description, "Initialize the list of countries " )
              @( author, "Ken O. Burtch" );
pragma license( gplv3 );
pragma software_model( shell_script );

with separate "../lib/common.inc.sp";
with separate "../lib/key_codes.inc.sp";
with separate "../lib/urls.inc.sp";

-- SET ATTACK VECTOR
--
-- Setup an web log attack vector substring by adding it to the hash table.
-----------------------------------------------------------------------------

  procedure set_attack_vector( v : in out an_attack_vector ) is
     key_code : key_codes;
     key_code_string : string;
     old_v : an_attack_vector;
  begin
     key_code := to_key_code( string( v.vector ) );
     key_code_string := strings.image( key_code );
     if btree_io.has_element( avectors_file, key_code_string ) then
        btree_io.get( avectors_file, key_code_string, old_v );
        old_v.vector := @ & ASCII.LF & v.vector;
        btree_io.set( avectors_file, key_code_string, old_v );
     else
        btree_io.set( avectors_file, key_code_string, v );
     end if;
  end set_attack_vector;

v : an_attack_vector;
f : file_type;
s : attack_vector_string;

begin

  btree_io.create( avectors_file, "../" & string( avectors_path ), avectors_width, avectors_width );
  open( f, in_file, "../data/attack_vectors.txt" );
  while not end_of_file( f ) loop
     s := get_line( f );
     v.vector := s;
     v.kind := forbidden_vector;
     v.handling := block_vector;
     v.comment := "";
     set_attack_vector( v );
  end loop;
  btree_io.close( avectors_file );

end init_http_vectors;

-- vim: ft=spar

