separate;

------------------------------------------------------------------------------
-- This file contains definitions for geolocation
------------------------------------------------------------------------------

type country_data is record
   iso3166 : string;
   common_name : string;
   suffix : string;
end record;

countries_path : constant string := "data/countries.btree";
countries_width : constant positive := 128;

-- vim: ft=spar
