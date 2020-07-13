#
# (C) Tenable Network Security
#




if(description)
{
 script_id(12071);
 script_bugtraq_id(9711);
 script_version("$Revision: 1.3 $");
 name["english"] = "JigSaw < 2.2.4";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host appears to be running a version of the JigSaw web server 
which is older than 2.2.4.

This version is vulnerable to a bug in the way it parses URI.

An attacker might exploit this flaw to execute arbitrary code on this host.

Solution : Upgrade to version 2.2.4 when it is available
See also : http://jigsaw.w3.org/
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for version of JigSaw";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Misc.";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);


banner = get_http_banner(port: port);
if(!banner)exit(0);
 
if(egrep(pattern:"^Server: Jigsaw/([01]\.|2\.([01]\.|2\.[0-3][^0-9])).*", string:banner))
 {
   security_hole(port);
 }
