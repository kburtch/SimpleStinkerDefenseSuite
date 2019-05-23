separate;

------------------------------------------------------------------------------
-- This file is for tracking and evaluating login names
------------------------------------------------------------------------------

------------------------------------------------------------------------------
-- SUSPICIOUS LOGINS
------------------------------------------------------------------------------

type login_kind is (
   privileged_login,
   service_login,
   dictionary_login,
   existing_login,
   unknown_login_kind,
   role_login,
   guest_login,
   data_service_login,
   calling_card
);

type a_sshd_login is record
     username   : user_string;
     count      : natural;
     ssh_disallowed : boolean;
     kind       : login_kind;
     comment    : comment_string;
     created_on : timestamp_string;
     logged_on  : timestamp_string;
     updated_on : timestamp_string;
     data_type       : data_types;
end record;
pragma assumption( applied, a_sshd_login );

sshd_logins_path : constant file_path := "data/sshd_logins.btree";
pragma assumption( used, sshd_logins_path );
sshd_logins_buffer_width : constant positive := 2048;
pragma assumption( used, sshd_logins_buffer_width );

------------------------------------------------------------------------------
-- KNOWN LOGINS
------------------------------------------------------------------------------

-- CHECK KNOWN LOGINS
--
-- Read the password file and make a list of known logins.
------------------------------------------------------------------------------
pragma todo( team,
  "doesn't handle active directory type services...only local",
  work_measure.unknown, 0,
  work_priority.level, 'l' );

known_logins : dynamic_hash_tables.table( user_string );

procedure check_known_logins is
  f : file_type;
  s : string;
  user : user_string;
begin
  open( f, in_file, "/etc/passwd" );
  while not end_of_file( f ) loop
     s := get_line( f );
     user := user_string( strings.field( s, 1, ":" ) );
     dynamic_hash_tables.set( known_logins, user, user );
  end loop;
  close( f );
end check_known_logins;
pragma assumption( used, check_known_logins );

-- vim: ft=spar
