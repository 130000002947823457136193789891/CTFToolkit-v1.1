#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# 
# Ref: Jeremy Bae
#
# This script is released under the GNU GPL v2

if(description)
{
  script_id(16059);
  script_cve_id("CAN-2004-1419");
  script_bugtraq_id(12103);
  script_version("$Revision: 1.3 $");
  
  script_name(english:"ZeroBoard flaws");

 desc["english"] = "
The remote host runs ZeroBoard, a web BBS application.

The remote version of this software is vulnerable to cross-site scripting 
and remote script injection due to a lack of sanitization of user-supplied 
data.

Successful exploitation of this issue may allow an attacker to execute 
arbitrary code on the remote host or to use it to perform an attack against
third-party users.

Solution: Upgrade to the latest version of this software
Risk factor : High";

  script_description(english:desc["english"]);
  script_summary(english:"Checks ZeroBoard flaws");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
  script_family(english:"CGI abuses : XSS");
  script_require_ports("Services/www", 80);
  script_dependencie("http_version.nasl", "cross_site_scripting.nasl");
  exit(0);
}

#the code

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! get_port_state(port))exit(0);
if ( ! can_host_php(port:port) ) exit(0);

if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);

buf = http_get(item:"/check_user_id.php?user_id=<script>foo</script>", port:port);
r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
if( r == NULL )exit(0);

if("ZEROBOARD.COM" >< r && egrep(pattern:"<script>foo</script>", string:r))
{
  security_hole(port);
  exit(0);
}
