#
# (C) Tenable Network Security
#


if(description)
{
 script_id(15951);
 script_bugtraq_id(11900);
 if (defined_func("script_xref")) {
  script_xref(name:"OSVDB", value:"12364");
  script_xref(name:"OSVDB", value:"12365");
  script_xref(name:"OSVDB", value:"12366");
  script_xref(name:"OSVDB", value:"12367");
 }
 script_version("$Revision: 1.5 $");
 name["english"] = "UBB.threads Cross Site Scripting Vulnerabilities";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running UBB.threads, a bulletin board system written in PHP.

There are various cross-site scripting issues in the remote version of this
software. An attacker may exploit them to use the remote website to conduct
attacks against third parties.

Solution : Upgrade to the latest version of this software
Risk factor : Medium";


 script_description(english:desc["english"]);
 
 summary["english"] = "XSS UBB.threads";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2004-2005 Tenable Network Security");
 family["english"] = "CGI abuses : XSS";
 script_family(english:family["english"]);
 script_dependencie("cross_site_scripting.nasl", "ubbthreads_detect.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);

if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);
if(!get_port_state(port))exit(0);
if ( ! can_host_php(port:port) ) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/ubbthreads"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
 loc = matches[2];
 res = http_keepalive_send_recv(port:port, data:http_get(item:loc + "/calendar.php?Cat=<script>foo</script>", port:port), bodyonly:1);
 if ( res == NULL ) exit(0);
 if ( "<script>foo</script>" >< res ) security_warning(port);
}
