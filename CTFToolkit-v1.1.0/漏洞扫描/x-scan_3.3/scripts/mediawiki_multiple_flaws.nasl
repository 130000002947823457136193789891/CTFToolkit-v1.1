#
# (C) Tenable Network Security
#

if(description)
{
 script_id(18035);
 if ( NASL_LEVEL >= 2200 )script_bugtraq_id(12625, 12444, 12305, 11985, 11897, 11480, 11416, 11302, 10958, 9057);
 script_version("$Revision: 1.2 $");
 
 script_name(english:"MediaWiki Multiple Remote Vulnerabilities");
 desc["english"] = "
The remote host seems to be running MediaWiki, a wiki web application 
written in PHP.

The remote version of this software is vulnerable to various vulnerabilities
which may allow an attacker to execute arbitrary PHP code on the remote host.

Solution: Upgrade to version 1.3.11 of this software or a newer version
Risk factor : High";

 script_description(english:desc["english"]);
 script_summary(english:"Test for the version of MedaWiki");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 script_dependencie("http_version.nasl");
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

foreach d (cgi_dirs())
{
 req = http_get(item:string(d, "/RELEASE-NOTES"), port:port);
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( res == NULL ) exit(0);
 if ( "MediaWiki" >< res &&
      "Version 1.4" >!< res &&
      ( "Version 1.2" >< res || 
        ("Version 1.3" >< res && "Version 1.3.11" >!< res ) ) )
	security_hole(port);
}
