#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11395);
 script_bugtraq_id(1594, 1595);
 script_version ("$Revision: 1.9 $");
 script_cve_id("CAN-2000-0746");

 name["english"] = "Microsoft Frontpage XSS";
 script_name(english:name["english"]);

 desc["english"] = "
The remote server is vulnerable to Cross-Site-Scripting (XSS)
when the FrontPage CGI /_vti_bin/shtml.dll is fed with improper
arguments.

Solution : See http://www.microsoft.com/technet/security/bulletin/ms00-060.mspx
Risk factor : Medium";



 script_description(english:desc["english"]);

 summary["english"] = "Checks for the presence of a Frontpage XSS";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);


 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003 Renaud Deraison");
 family["english"] = "CGI abuses : XSS";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl", "cross_site_scripting.nasl", "www_fingerprinting_hmap.nasl");
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
sig = get_kb_item("www/hmap/" + port + "/description");
if ( sig && "IIS" >!< sig ) exit(0);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);

req = http_get(item:"/_vti_bin/shtml.exe/<script>alert(document.domain)</script>", port:port);

res = http_keepalive_send_recv(port:port, data:req);
if( res == NULL ) exit(0);
if ( ereg(pattern:"^HTTP/.* 404 .*", string:res)) exit(0);

res2 = strstr(res, '\r\n\r\n');
if ( ! res2 ) res2 = strstr(res, '\n\n');
if ( ! res2 ) exit(0);

if("<script>alert(document.domain)</script>" >< res2)security_warning(port);
