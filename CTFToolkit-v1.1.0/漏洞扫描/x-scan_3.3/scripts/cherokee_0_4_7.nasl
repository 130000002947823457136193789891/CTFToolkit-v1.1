#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
#  (C) Tenable Network Security
#
#  Ref: César Fernández 
#
#  This script is released under the GNU GPL v2
#

if(description)
{
 script_id(15618);
 script_bugtraq_id(9496);
 if ( defined_func("script_xref") ) script_xref(name:"OSVDB", value:3707);

 script_version("$Revision: 1.4 $");
 name["english"] = "Cherokee error page XSS";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running Cherokee - a fast and tiny web server.

The remote version of this software is vulnerable to cross-site
scripting attacks due to lack of sanitization in returned error pages.

Solution : Upgrade to Cherokee 0.4.8 or newer
Risk factor : Low";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for version of Cherokee";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 family["english"] = "CGI abuses : XSS";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 443);
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
 
serv = strstr(banner, "Server");
if(ereg(pattern:"^Server:.*Cherokee/0\.([0-3]\.|4\.[0-7])[^0-9]", string:serv))
 {
   security_hole(port);
 }
