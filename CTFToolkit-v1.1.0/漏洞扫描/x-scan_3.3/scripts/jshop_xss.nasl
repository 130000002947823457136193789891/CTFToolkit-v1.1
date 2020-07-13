#
# Script by Noam Rathaus
#
# From: "Dr Ponidi" <drponidi@hackermail.com>
# Date: 22.8.2004 15:53
# Subject: JShop Input Validation Hole in 'page.php' Permits Cross-Site Scripting Attacks

if(description)
{
 script_id(14352);
 script_bugtraq_id(12403, 11003, 9609);
 script_version("$Revision: 1.6 $");
 
 name["english"] = "JShop Cross-Site Scripting Vulnerability";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running J-Shop, an e-Commerce suite written in PHP.

The remote version of this software is vulnerable to a cross-site scripting
attack.
An attacker can exploit it by compromising the parameters to the files
help.php and/or search.php.

This can be used to take advantage of the trust between a client and server 
allowing the malicious user to execute malicious JavaScript on 
the client's machine.

Solution : Upgrade to the latest version of this software
Risk factor: Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of an XSS bug in JShop";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
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
if(!can_host_php(port:port))exit(0);
if (  get_kb_item(string("www/", port, "/generic_xss")) ) exit(0);

function check(loc)
{
 req = http_get(item:string(loc, "/page.php?xPage=<script>alert(document.cookie)</script>"), port:port);

 r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( r == NULL )exit(0);
 if('<script>alert(document.cookie)</script>' >< r )
 {
 	security_warning(port);
	exit(0);
 }
}

foreach dir (cgi_dirs())
{
 check(loc:dir);
}

