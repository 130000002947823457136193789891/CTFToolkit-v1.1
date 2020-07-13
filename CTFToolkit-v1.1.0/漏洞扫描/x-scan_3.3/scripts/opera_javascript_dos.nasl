#
# (C) Tenable Network Security
#

if(description)
{
 script_id(14336);
 script_bugtraq_id(10997);
 
 script_version("$Revision: 1.3 $");
 name["english"] = "Opera Javascript Denial of Service";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using Opera - an alternative web browser.
This version is vulnerable to a remote denial of service.

An attacker may cause the browser to crash by crafting a rogue
HTML page containing a specific JavaScript command.

Solution : Install Opera 7.24 or newer.
Risk factor : Low";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the version of Opera.exe";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("opera_multiple_flaws.nasl");
 script_require_keys("Host/Windows/Opera/Version");
 exit(0);
}

v = get_kb_item("Host/Windows/Opera/Version");
if(strlen(v))
{
  v2 = split(v, sep:'.', keep:FALSE);
  if(int(v2[0]) < 7 || (int(v2[0]) == 7 && int(v2[1]) < 24))security_warning(port);
}
