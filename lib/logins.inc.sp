separate;

------------------------------------------------------------------------------
-- This file is for tracking and evaluating login names
------------------------------------------------------------------------------

------------------------------------------------------------------------------
-- LOGIN ACCOUNTS
------------------------------------------------------------------------------

type a_login_existence is (
   unknown_existence,
   active_existence,
   disabled_existence,
   no_existence
);

type a_sshd_login is record
     username   : user_string;
     count      : natural;
     kind       : login_kind;
     comment    : comment_string;
     created_on : timestamp_string;
     logged_on  : timestamp_string;
     updated_on : timestamp_string;
     data_type  : data_types;
     existence  : a_login_existence;
end record;
pragma assumption( applied, a_sshd_login );

sshd_logins_path : constant file_path := "data/sshd_logins.btree";
pragma assumption( used, sshd_logins_path );
pragma assumption( factor, sshd_logins_path );
sshd_logins_buffer_width : constant positive := 2048;
pragma assumption( used, sshd_logins_buffer_width );
pragma assumption( factor, sshd_logins_buffer_width );


-----------------------------------------------------------------------------
-- Exported Subprograms
-----------------------------------------------------------------------------


procedure check_known_logins;
pragma assumption( used, check_known_logins );

procedure init_login( login_rec : in out a_sshd_login; created_on : timestamp_string; logged_on : timestamp_string );
pragma assumption( used, init_login );


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


-- INIT LOGIN
--
-- Initialize a login record with reasonable defaults.
------------------------------------------------------------------------------

procedure init_login( login_rec : in out a_sshd_login; created_on : timestamp_string; logged_on : timestamp_string ) is
begin
  login_rec.count := 1;
  login_rec.data_type := real_data;
  login_rec.comment := "";
  login_rec.logged_on := logged_on;
  login_rec.existence := disabled_existence;
  login_rec.kind := unknown_login_kind;
  login_rec.created_on := created_on;
end init_login;

-- vim: ft=spar
