#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# 
# Ref: Donato Ferrante <fdonato@autistici.org>
#
# This script is released under the GNU GPL v2

if(description)
{
  script_id(16058);
  script_bugtraq_id(12104);
  script_version("$Revision: 1.2 $");
  
  script_name(english:"YACY Peer-To-Peer Search Engine XSS");

 desc["english"] = "
The remote host runs YACY, a Java Freeware Open-Source Caching 
HTTP Proxy and Global P2P-Based Search Engine.

The remote version of this software is vulnerable to multiple cross-site 
scripting due to a lack of sanitization of user-supplied data.

Successful exploitation of this issue may allow an attacker to use the
remote server to perform an attack against a third-party user.

Solution: Upgrade to the latest version of this software
Risk factor : Medium";

  script_description(english:desc["english"]);
  script_summary(english:"Checks YACY Peer-To-Peer Search Engine XSS");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
  script_family(english:"CGI abuses : XSS");
  script_require_ports("Services/www", 8080);
  script_dependencie("cross_site_scripting.nasl");
  exit(0);
}

#the code

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:8080);
if ( ! get_port_state(port))exit(0);
if ( ! can_host_php(port:port) ) exit(0);

if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);

buf = http_get(item:"/index.html?urlmaskfilter=<script>foo</script>", port:port);
r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
if( r == NULL )exit(0);

if(egrep(pattern:"<title>YACY: Search Page</title>.*<script>foo</script>", string:r))
{
  security_warning(port);
  exit(0);
}
