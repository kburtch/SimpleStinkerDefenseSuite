separate;

------------------------------------------------------------------------------
-- This file contains definitions for URL attack vectors
------------------------------------------------------------------------------

type attack_vector_string is new string;
type http_status_string is new string;
pragma assumption( applied, http_status_string );

--type url_string is new string;

type attack_vector_kinds is ( unknown_vector, forbidden_vector, suspicious_vector );

type attack_vector_handling is ( block_vector, whitelist_vector );

type an_attack_vector is record
  vector   : attack_vector_string;
  kind     : attack_vector_kinds;
  handling : attack_vector_handling;
  comment  : comment_string;
end record;

vectors_file  : btree_io.file( an_attack_vector );
vectors_path  : file_path := "data/http_vectors.btree";
vectors_width : natural := 2048;

-- vim: ft=spar
