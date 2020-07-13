#
# Script by Noam Rathaus
#
# From: Bartek Nowotarski <silence10@wp.pl>
# Subject: Cross Site Scripting in Moodle < 1.3
# Date: 2004-04-30 23:34

if(description)
{
 script_id(12222);
 script_cve_id("CAN-2004-1978");
 script_bugtraq_id(10251);
 script_version ("$Revision: 1.6 $"); 
 name["english"] = "Moodle XSS";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using Moodle, a course management system (CMS).
There is a bug in this software that makes it vulnerable to cross 
site scripting attacks.

An attacker may use this bug to steal the credentials of the 
legitimate users of this site.

Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of an XSS bug in Moodle";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Noam Rathaus");
 family["english"] = "CGI abuses : XSS";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "cross_site_scripting.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

function check(loc)
{
 req = http_get(item:string(loc, "/help.php?text=%3Cscript%3Efoo%3C/script%3E"),
                port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( r == NULL ) exit(0);
 if(egrep(pattern:"<script>foo</script>", string:r))
 {
        security_warning(port);
        exit(0);
 }
}


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);
if (  get_kb_item(string("www/", port, "/generic_xss")) ) exit(0);


check(loc:"/moodle");
foreach dir (cgi_dirs())
{
 check(loc:dir);
}

