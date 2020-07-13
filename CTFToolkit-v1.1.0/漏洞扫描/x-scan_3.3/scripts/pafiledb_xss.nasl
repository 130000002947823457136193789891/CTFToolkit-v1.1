#
# written by Renaud Deraison
#
# Subject: paFileDB 3.x SQL Injection Vulnerability
# From: <ersatz@unixhideout.com>
# To: bugtraq@securityfocus.com
# Subject: XSS vulnerabilites in Pafiledb


if (description)
{
 script_id(11479);
 script_cve_id("CAN-2002-1931");
 script_bugtraq_id(6021);
 script_version ("$Revision: 1.13 $");
 
 script_name(english:"paFileDB XSS");
 desc["english"] = "
The remote pafiledb.php is vulnerable to a cross site scripting
attack.

An attacker may use this flaw to steal the cookies of your users

Solution : Upgrade to paFileDB 3.0.
Risk factor : Medium";

 script_description(english:desc["english"]);
 script_summary(english:"Determine if pafiledb is vulnerable to XSS");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses : XSS", francais:"Abus de CGI");
 script_copyright(english:"This script is Copyright (C) 2003-2005 Renaud Deraison");
 script_dependencie("pafiledb_detect.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);

# Test an install.
install = get_kb_item(string("www/", port, "/pafiledb"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
 d = matches[2];
 url = string(d, '/pafiledb.php?action=download&id=4?"<script>alert(foo)</script>"');
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( buf == NULL ) exit(0);
 
 if("<script>alert(foo)</script>" >< buf)
   {
    security_warning(port);
    exit(0);
   }
}
