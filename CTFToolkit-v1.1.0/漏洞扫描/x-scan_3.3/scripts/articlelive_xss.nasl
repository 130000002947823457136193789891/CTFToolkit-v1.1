#
# Script by Noam Rathaus GPLv2
#
# Interspire ArticleLive 2005 (php version) XSS vulnerability
# mircia <mircia@security.talte.net>
# 2005-03-24 14:54

if(description)
{
 script_id(17612);
 script_version("$Revision: 1.2 $");
 script_cve_id("CAN-2005-0881");
 script_bugtraq_id(12879);
 
 name["english"] = "Interspire ArticleLive 2005 XSS Vulnerability";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running ArticleLive, a set of CGIs designed to simplify
the management of a news site.

Due to improper filtering done by the script 'newcomment' remote attacker
can cause the ArticleLive product to include arbitrary HTML and/or
JavaScript, and therefore use the remote host to perform cross-site
scripting attacks.

Solution : Upgrade to the newest version of this software
Risk factor: Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of a ArticleLive XSS";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2005 Noam Rathaus");
 family["english"] = "CGI abuses : XSS";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "cross_site_scripting.nasl", "http_version.nasl");
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
 req = http_get(item: string(loc, '/newcomment/?ArticleId="><script>foo</script>'), port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( r == NULL )exit(0);
 if('value=""><script>foo</script>"' >< r)
 {
  security_warning(port);
  exit(0);
 }
}

foreach dir ( cgi_dirs() )
{
 check(loc:dir);
}

