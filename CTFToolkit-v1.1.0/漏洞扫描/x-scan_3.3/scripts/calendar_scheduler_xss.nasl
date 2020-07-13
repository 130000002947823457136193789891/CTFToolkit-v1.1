#
# Script by Noam Rathaus GPLv2
#
# "Alberto Trivero" <trivero@jumpy.it>
# Multiple vulnerabilities in Topic Calendar 1.0.1 for phpBB
# 2005-03-24 02:14

if(description)
{
 script_id(17613);
 script_version("$Revision: 1.2 $");

 script_cve_id("CAN-2005-0872");
 script_bugtraq_id(12893);
 
 name["english"] = "Topic Calendar XSS";

 script_name(english:name["english"]);
 
 desc["english"] = "
Topic Calendar is a quite widespread MOD for phpBB all versions that adds
a calendar to the board, using topics as event. 

Due to improper filtering done by the script 'calendar_scheduler.php' a
remote attacker can cause the Topic Calendar product to include arbitrary
HTML and/or JavaScript.

An attacker may use this bug to preform phishing attacks.

Solution : Disable this mod or upgrade to a newer version
Risk factor: Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of a Topic Calendar XSS";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2005 Noam Rathaus");
 family["english"] = "CGI abuses : XSS";
 script_family(english:family["english"]);
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
 req = http_get(item: string(loc, '/calendar_scheduler.php?start="><script>foo</script>'), port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( r == NULL )exit(0);
 if('start="><script>alert(document.cookie)</script>" class=' >< r)
 {
  security_warning(port);
  exit(0);
 }
}

foreach dir ( cgi_dirs() )
{
 check(loc:dir);
}

