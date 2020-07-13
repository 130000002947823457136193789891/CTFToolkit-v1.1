#
# This script was written by Noam Rathaus
#
# GPLv2
#
# From: David S. Ferreira [iamroot@systemsecure.org]
# Subject: My Little Forum XSS Attack
# Date: Tuesday 23/12/2003 08:20
#
#

if(description)
{

  script_id(11960);
  script_version("$Revision: 1.7 $");
  name["english"] = "My Little Forum XSS Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
The remote host is running 'My Little Forum', a free CGI suite to manage
discussion forums.

This PHP/MySQL based forum suffers from a Cross Site Scripting vulnerability.
This can be exploited by including arbitrary HTML or even JavaScript code in
the parameters (forum_contact, category and page), which will be executed in
user's browser session when viewed.

Risk factor : Medium";

  script_description(english:desc["english"]);
 
  summary["english"] = "Detect My Little Forum XSS";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2003 Noam Rathaus");

  family["english"] = "CGI abuses : XSS";
  script_family(english:family["english"]);
  script_dependencie("find_service.nes", "http_version.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);

if (!get_port_state(port) ) exit(0);
if (!can_host_php(port:port)) exit(0);

if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);


quote = raw_string(0x22);

function check_dir(path)
{
 req = http_get(item:string(path, "/forum/email.php?forum_contact=", quote, "><script>foo</script>"), port:port);

 res = http_keepalive_send_recv(port:port, data:req, bodyonly:1);

 if ( res == NULL ) exit(0);
 find = "<script>foo</script>";

 if ( find >< res ) 
 {
  security_warning(port);
  exit(0);
 }
}

foreach dir (cgi_dirs())
{
 check_dir(path:dir);
}
