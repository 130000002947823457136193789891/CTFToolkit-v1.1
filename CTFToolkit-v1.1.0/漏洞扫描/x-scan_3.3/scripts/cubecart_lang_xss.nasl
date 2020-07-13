#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# Ref: John Cobb
# This script is released under the GNU GPL v2
#

if(description)
{
  script_id(17227);
  script_bugtraq_id(12549);
  script_cve_id("CAN-2005-0443");
  if ( defined_func("script_xref") ) script_xref(name:"OSVDB", value:"14062");
   
  script_version("$Revision: 1.2 $");
  script_name(english:"Brooky CubeCart index.php language XSS");

 desc["english"] = "
The remote host runs CubeCart, is an eCommerce script written with PHP & MySQL.

This version is vulnerable to cross-site scripting and remote script 
injection due to a lack of sanitization of user-supplied data.
Successful exploitation of this issue may allow an attacker to execute 
malicious script code on a vulnerable server. 

Solution: Upgrade to version 2.0.5 or higher
Risk factor : Medium";

  script_description(english:desc["english"]);
  script_summary(english:"Checks Brooky CubeCart language XSS");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005 David Maciejak");
  script_family(english:"CGI abuses");
  script_require_ports("Services/www", 80);
  script_dependencie("cross_site_scripting.nasl", "cubecart_detect.nasl");
  exit(0);
}

#the code

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! get_port_state(port))exit(0);
if ( ! can_host_php(port:port) ) exit(0);

if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/cubecart"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  loc = matches[2];

  buf = http_get(item:string(loc,"/index.php?&language=<script>foo</script>"), port:port);
  r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);

  if(egrep(pattern:"<script>foo</script>", string:r))
    security_warning(port);
}
