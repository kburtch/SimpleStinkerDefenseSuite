separate;

-----------------------------------------------------------------------------
-- Notes on implementation
--
-- For our purposes, we will:
--
-- 1. Group attack vector substrings into categories called key codes.
-- 2. Record the key codes in the web request.
-- 3. Finally, check the web request for the attack vectors starting with
--   those key codes.
--
-- This is an attempt to filter out substrings by ignoring substrings that
-- start with characters not in the request.  It also attempts to each for
-- each substring no more than once.
--
-- Originally, using a keycode from 1..30 (basically, a single letter) often
-- generated 23 to 27 matches out of 30 (only filtering out 10% to 24% of
-- search strings).  Two characters gave 50% to 80% filtering out.
--
-- There is no doubt room for improvement, but there aren't a lot of
-- attack substrings yet.
--
-- Substring search approaches such as Rabin-Karp are either too inefficient
-- to implement without pointers, or are just overkill for the number of
-- strings we have.
-----------------------------------------------------------------------------

-----------------------------------------------------------------------------
-- Key Codes
--
-- The hash table key codes are a number from 1..30, each number representing
-- the first character of a string.  In some cases, characters are grouped
-- under one number.  The number 30 is for catch-all / ignored cases.
-----------------------------------------------------------------------------

  key_code_constraint_error : exception;

  type key_codes is new positive
    affirm
      raise key_code_constraint_error when key_codes not in 1..30;
    end affirm;

-----------------------------------------------------------------------------
-- Exported Subprograms
-----------------------------------------------------------------------------


  function to_key_code( candidate : string ) return key_codes;


-- TO BASIC KEY CODE
--
-- Return the hash key code for a single character.  "Basic" here means if
-- the key code is 30, it is returned as-is.
-----------------------------------------------------------------------------

  function to_basic_key_code( ch : character ) return key_codes is
    letter : key_codes;
  begin
    if ch in 'A'..'Z' then
       letter := key_codes( numerics.pos( ch )-64 );
    elsif ch in 'a'..'z' then
       letter := key_codes( numerics.pos( ch )-96 );
    elsif ch in '0'..'9' then
       letter := 27;
    -- special cases
    elsif ch = '/' then
       letter := 30;
    elsif ch = '?' then
       letter := 30;
    elsif ch = '&' then
       letter := 30;
    elsif ch <= 'A' then
       letter := 28;
    elsif ch > 'Z' then
       letter := 29;
    else
       letter := 30;
    end if;
--put( ch ) @ (letter); new_line;
    return letter;
  end to_basic_key_code;


-- TO KEY CODE
--
-- Return the hash key code for a string.  If the first character is code 30,
-- keep looking at subsequent characters until you get a non-30 code.
-----------------------------------------------------------------------------

  function to_key_code( candidate : string ) return key_codes is
    key_code : key_codes;
    key_code_1 : key_codes;
    key_code_2 : key_codes;
    ch : character;
    p : positive := 1;
  begin
--put_line( candidate );
--put( "key_code: " ) @ ( strings.element( candidate, i ) ) @ ( key_code );
--new_line;

    --key_code := 30;
    --for i in 1..strings.length( candidate ) loop
    --    key_code := to_basic_key_code( strings.element( candidate, i ) );
    --    exit when key_code /= 30;
    --end loop;

    key_code_1 := 30;
    while p <= strings.length( candidate ) loop
       ch := strings.element( candidate, p );
       key_code_1 := to_basic_key_code( ch );
       exit when key_code_1 /= 30;
       p := @+1;
    end loop;

    p := @+1;
    key_code_2 := 30;
    while p <= strings.length( candidate ) loop
       ch := strings.element( candidate, p );
       key_code_2 := to_basic_key_code( ch );
       exit when key_code_2 /= 30;
       p := @+1;
    end loop;

    key_code := key_code_2 + 30 * ( key_code_1 -1 );

--log_info( source_info.source_location ) @
--   ( candidate ) @ ( " => key_code " ) @ ( strings.image( integer( key_code ) ) );

    return key_code;
  end to_key_code;

-- vim: ft=spar

