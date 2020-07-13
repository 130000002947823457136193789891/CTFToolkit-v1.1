#
# This script was written by Renaud Deraison
#

if (description)
{
 script_id(11440);
 script_bugtraq_id(5517);
 script_version ("$Revision: 1.7 $");
 
 script_cve_id("CAN-2003-0152", "CAN-2003-0153", "CAN-2003-0154", "CAN-2003-0155");
		

 script_name(english:"Bonsai Mutiple Flaws");
 desc["english"] = "
The remote host has the CGI suite 'Bonsai' installed.

This suite is used to browse a CVS repository with a web browser.

The remote Bonsai seems to be vulnerable to various flaws, ranging from
path disclosure and cross site scripting to remote command execution.

Solution : Upgrade to the latest version of Bonsai
Risk factor : High";

 script_description(english:desc["english"]);
 script_summary(english:"Determine if bonsai is vulnerable to xss attack");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses : XSS", francais:"Abus de CGI");
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);


dirs = make_list(cgi_dirs());
foreach d (dirs)
{
 url = string(d, "/cvslog.cgi?file=<SCRIPT>window.alert</SCRIPT>");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req);
 if( buf == NULL ) exit(0);
 
 if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 ", string:buf) &&
    "Rcs file" >< buf &&
     "<SCRIPT>window.alert</SCRIPT>" >< buf)
   {
    security_hole(port);
    exit(0);
   }
}
