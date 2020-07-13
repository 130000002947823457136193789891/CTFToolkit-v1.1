#
# Script by Noam Rathaus GPLv2
#
# "Boshcash" <boshcash@msn.com>
# 2004-12-24 20:41
# PHProxy XSS Bug

if(description)
{
 script_id(16069);
 script_version("$Revision: 1.3 $");
 script_bugtraq_id(12115);
 
 name["english"] = "PHProxy XSS";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running PHProxy, a web HTTP proxy written in PHP.
 
There is a bug in the remote version software which makes it vulnerable to 
HTML and JavaScript injection.

An attacker may use this bug to preform web cache poisoning, xss attack, etc.

Solution : Upgrade to the newest version of this software
Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of a PHProxy XSS";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2004 Noam Rathaus");
 family["english"] = "CGI abuses : XSS";
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

function check(loc)
{
 req = http_get(item: string(loc, "/index.php?error=<script>foo</script>"), port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( r == NULL )exit(0);
 if("<script>foo</script>" >< r)
 {
  security_warning(port);
  exit(0);
 }
}

foreach dir ( cgi_dirs() )
{
 check(loc:dir);
}

