#
# Script by Noam Rathaus GPLv2
#
# Cross Site Scripting In PsychoStats 2.2.4 Beta && Earlier
# "GulfTech Security" <security@gulftech.org>
# 2004-12-23 02:50

if(description)
{
 script_id(16057);
 script_version("$Revision: 1.3 $");
 script_cve_id("CAN-2004-1417");
 script_bugtraq_id(12089);
 
 name["english"] = "PsychoStats Login Parameter Cross-Site Scripting";

 script_name(english:name["english"]);
 
 desc["english"] = "
PsychoStats is a statistics generator for games. Currently there is support 
for a handful of Half-Life 'MODs' including Counter-Strike, Day of Defeat, 
and Natural Selection.

There is a bug in this software which makes it vulnerable to HTML and 
JavaScript injection. An attacker may use this flaw to use the remote
server to set up attacks against third-party users.

Solution : Upgrade to the newest version of this software.
Risk factor: Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of a PsychoStats XSS";
 
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
 req = http_get(item: string(loc, "/login.php?login=<script>foo</script>"), port:port);
 
 r = http_keepalive_send_recv(port:port, data:req);
 if( r == NULL )exit(0);
 if('"login" value="<script>foo</script>' >< r)
 {
  security_warning(port);
  exit(0);
 }
}

check(loc:"/");

foreach dir ( cgi_dirs() )
{
 check(loc:dir);
}
