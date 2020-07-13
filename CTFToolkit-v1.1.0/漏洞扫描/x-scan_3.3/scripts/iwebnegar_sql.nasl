#
# (C) Tenable Network Security
#


if(description)
{
 script_id(15972);
 script_bugtraq_id(11946, 12140);
 script_version("$Revision: 1.4 $");
 name["english"] = "Multiple vulnerabilities in iWebNegar";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host appears to be running iWebNegar, a web log application
written in PHP.

There is a flaw in the remote software which may allow anyone
to inject arbitrary SQL commands, which may in turn be used to
gain administrative access on the remote host. 

Additionally, the remote version of this software is vulnerable to several
flaws which may allow an attacker to reset the configuration of the remote
service without any credentials or to perform a cross site scripting attack
using the remote host.

Solution : Upgrade to the latest version of this software
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "SQL Injection";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "CGI abuses : XSS";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");



port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if ( ! can_host_php(port:port) ) exit(0);


foreach dir (cgi_dirs()) 
 {
  req = http_get(item:dir + "/index.php?string='", port:port);
  res = http_keepalive_send_recv(port:port, data:req);
  if ( res == NULL ) exit(0);
  if ("iWebNegar" >< res &&
     egrep(pattern:"mysql_fetch_array\(\).*MySQL", string:res) ) 
	{
	  security_hole(port);
	  exit(0);
	}
 }
