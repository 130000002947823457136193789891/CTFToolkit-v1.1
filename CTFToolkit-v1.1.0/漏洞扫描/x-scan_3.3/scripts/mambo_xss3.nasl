#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  Released under the GNU GPL v2
#  Ref: JeiAr   - GulfTech Security Research Team
#

if (description)
{
 script_id(16316);
 script_cve_id("CAN-2004-1825");
 script_bugtraq_id(9890);
 if ( defined_func("script_xref") ) {
  script_xref(name:"OSVDB", value:"4308");
  script_xref(name:"OSVDB", value:"4665");
 }
 script_version ("$Revision: 1.3 $");

 script_name(english:"Mambo Site Server index.php mos_change_template XSS");
 desc["english"] = "
An attacker may use the installed version of Mambo Site Server to
perform a cross site scripting attack on this host. 

Solution: Upgrade at least to version 4.5 1.0.4
Risk factor : Medium";

 script_description(english:desc["english"]);
 script_summary(english:"Determine if Mambo Site Server is vulnerable to xss attack");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses : XSS");
 script_copyright(english:"This script is Copyright (C) 2005 David Maciejak");
 script_dependencie("mambo_detect.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);
if(!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/mambo_mos"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
 dir = matches[2];

 url = string(dir, "/index.php?mos_change_template=<script>foo</script>");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( buf == NULL ) exit(0);
 
 if ( '<form action="/index.php?mos_change_template=<script>foo</script>' >< buf )
    security_warning(port);
}
