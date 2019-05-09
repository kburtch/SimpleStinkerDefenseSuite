#!/usr/local/bin/spar

with separate "config/contributors.inc.sp";
with separate "lib/world.inc.sp";
with separate "config/config.inc.sp";

procedure lookup_ip is
  pragma annotate( summary, "lookup_ip ip_number" )
                @( description, "Write a report on a single IP number" )
                @( description, "to standard output." )
                @( author, "Ken O. Burtch" )
                @( param, "ip_number - the ip number" );
  pragma license( gplv3 );
  pragma software_model( shell_script );

  with separate "lib/common.inc.sp";
  with separate "lib/blocking.inc.sp";
  with separate "lib/countries.inc.sp";
  with separate "lib/reports.inc.sp";

-- USAGE
--
-- Show the help
-----------------------------------------------------------------------------

procedure usage is
begin
  help( source_info.enclosing_entity );
end usage;

offender_key : string;
must_quit    : boolean := false;

procedure handle_command_options( quit : out boolean ) is
  arg_pos : natural := 1;
  arg : string;
begin
  quit := false;
  while arg_pos <= command_line.argument_count loop
    arg := command_line.argument( arg_pos );
    if arg = "-h" or arg = "--help" then
       usage;
       quit;
    elsif arg_pos = command_line.argument_count then
       offender_key := arg;
    else
       put_line( standard_error, "unknown option: " & arg );
       quit;
    end if;
    arg_pos := @+1;
  end loop;
  if offender_key = "" and not quit then
     put_line( standard_error, "an ip number is required" );
     quit;
  end if;
end handle_command_options;

  offender : an_offender;

  countries_file : btree_io.file( country_data );
  country : country_data;
  country_name : string;
  found : boolean;

begin

  -- Process command options

  handle_command_options( must_quit );
  if must_quit  then
     command_line.set_exit_status( 1 );
     return;
  end if;

  btree_io.open( countries_file, string( countries_path ), countries_width, countries_width );
  btree_io.open( offender_file, string( offender_path ), offender_buffer_width, offender_buffer_width );

  begin
    btree_io.get( offender_file, offender_key, offender );
    found;
  exception when others =>
    found := false;
  end;

  if not found then
     put_line( offender_key & " is neither tracked nor blocked" );
     if btree_io.is_open( offender_file ) then
        btree_io.close( offender_file );
     end if;
     if btree_io.is_open( countries_file ) then
        btree_io.close( countries_file );
     end if;
     return;
  end if;

  country_name := "unknown";
  begin
    btree_io.get( countries_file, string( offender.source_country ), country );
    country_name := country.common_name;
  exception when others => null; --- TODO: fix this
  end;
  ip_report( offender, country_name );
exception when others =>
  if btree_io.is_open( offender_file ) then
     btree_io.close( offender_file );
  end if;
  if btree_io.is_open( countries_file ) then
     btree_io.close( countries_file );
  end if;
end lookup_ip;

-- vim: ft=spar

