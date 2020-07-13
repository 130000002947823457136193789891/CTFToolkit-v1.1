#
# Script by Noam Rathaus
#
# From: "Thomas Ryan" <tommy@providesecurity.com>
# Date: 7.7.2004 18:10
# Subject: Comersus Cart Cross-Site Scripting Vulnerability

if(description)
{
 script_id(12640);
 script_cve_id("CAN-2004-0681", "CAN-2004-0682");
 script_bugtraq_id(10674);
 script_version("$Revision: 1.5 $");
 
 name["english"] = "Comersus Cart Cross-Site Scripting Vulnerability";

 script_name(english:name["english"]);
 
 desc["english"] = "
The malicious user is able to compromise the parameters to invoke a
Cross-Site Scripting attack. This can be used to take advantage of the trust
between a client and server allowing the malicious user to execute malicious
JavaScript on the client's machine or perform a denial of service shutting
down IIS.

Solution: Upgrade to version 5.098 or newer
Risk factor: Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of an XSS bug in Comersus";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2004 Noam Rathaus");
 family["english"] = "CGI abuses : XSS";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("cross_site_scripting.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_asp(port:port))exit(0);
if (  get_kb_item(string("www/", port, "/generic_xss")) ) exit(0);

function check(loc)
{
 req = http_get(item:string(loc, "/comersus_message.asp?message=nessus<script>foo</script>"), port:port);

 r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( r == NULL )exit(0);
 if('<font size="2">nessus<script>foo</script>' >< r ) 
 {
 	security_warning(port);
	exit(0);
 }
}

check(loc:"/comersus/store");
foreach dir (cgi_dirs())
{
 check(loc:dir);
}
