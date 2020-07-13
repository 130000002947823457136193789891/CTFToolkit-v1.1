#
# This script is (C) Tenable Network Security
#
#

if(description)
{
 script_id(17210);
 script_bugtraq_id(12637, 12638);
 script_version ("$Revision: 1.1 $");
 name["english"] = "TWiki Multiple Vulnerabilties";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running Twiki, a wiki system written in Perl.

The remote version of this software is vulnerable to several input
validation vulnerabilities which may allow an attacker to execute
arbitary commands on the remote host with the privileges of the
web server.

Solution : Upgrade to the latest version of this software
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of TWiki";
 
 script_summary(english:summary["english"]);
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security",
		francais:"Ce script est Copyright (C) 2005 Tenable Network Security");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
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

function check(loc)
{
  res = http_keepalive_send_recv(port:port, data:http_get(item:loc + "/TWikiHistory.html", port:port), bodyonly:1);
  if ( res == NULL ) exit(0);
  if ( "TWiki Development Timeline" >< res  &&
	"01-Jul-1999 Release" >< res &&
       !egrep(pattern:"[0-9]*-.*-2005", string:res) )
		security_hole(port);
}


foreach dir ( cgi_dirs() )
{
 check(loc:dir);
}
