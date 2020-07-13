#
# (C) Tenable Network Security
#
#

if (description)
{
 script_id(16070);
 script_cve_id("CAN-2004-1420", "CAN-2004-1421", "CAN-2004-1422");
 script_bugtraq_id(12119);
 script_version ("$Revision: 1.2 $");

 script_name(english:"WHM AutoPilot Multiple Vulnerabilities");
 desc["english"] = "
The remote web server is running WHM AutoPilot, a script designed to
administer a web-hosting environment.

The remote version of this software is vulnerable to various flaws which
may allow an attacker to execute arbitrary commands on the remote host.

Solution : Upgrade the newest version of this software.
Risk factor : High";

 script_description(english:desc["english"]);
 script_summary(english:"Determines if WHM AutoPilot can include third-party files");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses", francais:"Abus de CGI");
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

foreach d (cgi_dirs())
{
 url = string(d, "/inc/header.php/step_one.php?server_inc=http://xxxx./");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req);
 if( buf == NULL ) exit(0);
 if ( "http://xxxx./step_one_tables.php" >< buf )
 {
  security_hole(port);
  exit(0);
 }
}
