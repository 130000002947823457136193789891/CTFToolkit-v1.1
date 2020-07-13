#
# Script by Noam Rathaus
#
# From: "DarkBicho" <darkbicho@fastmail.fm>
# Subject: Multiple vulnerabilities PowerPortal
# Date: 28.6.2004 03:42

if(description)
{
 script_id(12292);
 script_cve_id("CAN-2004-0662", "CAN-2004-0664");
 script_bugtraq_id(10622);
 script_version("$Revision: 1.3 $");
 
 name["english"] = "PowerPortal Path Dislcosure";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using PowerPortal, a content management system, 
written in PHP. 

A vulnerability exists in the remote version of this product which may allow 
a remote attacker to cause the product to disclose the path it is installed 
under. An attacker may use this flaw to gain more knowledge about the setup
of the remote host, and therefore prepare better attacks.

Solution : Upgrade to the latest version of this software.
Risk factor : Low";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of an Path Disclosure bug in PowerPortal";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Noam Rathaus");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
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

function check(loc)
{
 req = http_get(item:string(loc, "/modules.php?name=gallery&files=foobar"), port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( r == NULL )exit(0);
 if(egrep(pattern:"Warning:", string:r) && 
    egrep(pattern:"opendir", string: r) && 
    egrep(pattern:"failed to open dir: No such file or directory in", string:r))
 {
  security_warning(port);
  exit(0);
 }
}

check(loc:"/");
foreach dir (cgi_dirs())
{
 check(loc:dir);
}
