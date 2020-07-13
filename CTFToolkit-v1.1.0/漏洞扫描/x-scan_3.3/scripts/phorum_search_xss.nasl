#
# (C) Tenable Network Security
#

if(description)
{
 script_id(14185);
 script_bugtraq_id(10822);
 script_version ("$Revision: 1.3 $"); 
 name["english"] = "Phorum Search Cross Site Scripting Vulnerability";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using Phorum, a web forum package written in PHP.

The remote version of this package contains a script called 'search.php'
which is vulnerable to a cross site scripting attack. An attacker may
exploit this problem to steal the authentication credentials of third
party users.

Solution : Upgrade to the newest version of this software
Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of an XSS bug in Phorum";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2005 Tenable Network Security");
 family["english"] = "CGI abuses : XSS";
 script_family(english:family["english"]);
 script_dependencie("phorum_detect.nasl");
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


# Test an install.
install = get_kb_item(string("www/", port, "/phorum"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
 loc = matches[2];

 req = http_get(item:string(loc, "/search.php?f=1&search=<script>foo</script>&match=1&date=30&fldsubject=1"), port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( r == NULL ) exit(0);
 if(egrep(pattern:"<script>foo</script>", string:r))
 {
        security_warning(port);
 }
}
