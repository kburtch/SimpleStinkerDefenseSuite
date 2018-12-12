separate;

------------------------------------------------------------------------------
-- This file contains definitions for geolocation
------------------------------------------------------------------------------

type country_data is record
   iso3166 : string;
   common_name : string;
   suffix : string;
end record;

countries_path : constant file_path := "data/countries.btree";
pragma assumption( used, countries_path );

countries_width : constant positive := 128;
pragma assumption( used, countries_width );

-- vim: ft=spar
