#
# (C) Tenable Network Security
#
#

if (description)
{
 script_id(16071);
 script_cve_id("CAN-2004-1423");
 script_bugtraq_id(12127);
 script_version ("$Revision: 1.4 $");

 script_name(english:"PHP-Calendar Remote File Include Vulnerability");
 desc["english"] = "
The remote web server is running PHPCalendar, a web-based calendar
written in PHP. 

The remote version of this software is vulnerable to a file inclusion
flaw which may allow an attacker to execute arbitrary PHP commands on
the remote host.

Solution : Upgrade the newest version of this software.
Risk factor : High";

 script_description(english:desc["english"]);
 script_summary(english:"Determines if PHP-Calendar can include third-party files");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses", francais:"Abus de CGI");
 script_copyright(english:"This script is Copyright (C) 2004-2005 Tenable Network Security");
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
 url = string(d, "/includes/calendar.php?phpc_root_path=http://xxxx./");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req);
 if( buf == NULL ) exit(0);
 if ( "http://xxxx./includes/html.php" >< buf )
 {
  security_hole(port);
  exit(0);
 }
}
