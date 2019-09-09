separate;

------------------------------------------------------------------------------
-- This file is for tracking and evaluating hostnames and their variants
------------------------------------------------------------------------------

hostname_variants : dynamic_hash_tables.table( user_string );

hostname_full_alias : constant user_string := " HOSTNAME ";
hostname_host_alias : constant user_string := " HOSTNAME_HOST ";
hostname_base_alias : constant user_string := " HOSTNAME_BASE ";

-----------------------------------------------------------------------------
-- Exported Subprograms
-----------------------------------------------------------------------------


procedure create_login_hostname_variants( s : string; host : in out string; base : in out string );

procedure add_hostname_variants( s : in out string );

procedure register_login_hostname_variants;


-- CREATE LOGIN HOSTNAME VARIANTS
--
-- Given a standard www.foobar.com domain name, return
-- www as host and foobar as base.
------------------------------------------------------------------------------

procedure create_login_hostname_variants( s : string; host : in out string; base : in out string ) is
  p : natural;
  s1 : string := s;
begin
  host := "";
  base := "";
  p := strings.index( s1, '.' );
  if p > 1 then
     host := strings.delete( s1, p, strings.length( s ) );
     s1 := strings.delete( s1, 1, p );
     p := strings.index( s1, "." );
     if p > 1 then
        base := strings.delete( s1, p, strings.length( s1 ) );
     end if;
  end if;
end create_login_hostname_variants;

-- ADD HOSTNAME VARIANTS
--
-- Calculate the hostname variants and add the hostname and the variants
-- to the hostname_variants lookup table.
------------------------------------------------------------------------------

procedure add_hostname_variants( s : in out string ) is
  host : string;
  base : string;
begin
  create_login_hostname_variants( s, host, base );
  dynamic_hash_tables.add( hostname_variants, s, hostname_full_alias );
  if host /= "" then
     dynamic_hash_tables.add( hostname_variants, host, hostname_host_alias );
  end if;
  if base /= "" then
     dynamic_hash_tables.add( hostname_variants, base, hostname_base_alias );
  end if;
end add_hostname_variants;

-- REGISTER LOGIN HOSTNAME VARIANTS
--
-- Using the hostname command, find the hostname and aliases and add them to
-- the hostname_variants table
------------------------------------------------------------------------------

procedure register_login_hostname_variants is
  this_hostname : string;
  this_hostname_aliases : string;
  cnt : natural := 1;
  s   : string;
begin
  this_hostname := `hostname;`;
  this_hostname_aliases := `hostname -a`;
  add_hostname_variants( this_hostname );
  loop
    s := strings.field( this_hostname_aliases, cnt, " " );
    exit when s = "";
    add_hostname_variants( s );
    cnt := @+1;
  end loop;
end register_login_hostname_variants;

-- vim: ft=spar

