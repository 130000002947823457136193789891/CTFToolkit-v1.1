#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  Ref: Donato Ferrante <fdonato autistici org>
#
#  This script is released under the GNU GPL v2
#

if (description)
{
 script_id(16313);
 script_bugtraq_id(12451);
 if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"13575");
 }
 script_version ("$Revision: 1.2 $");

 script_name(english:"RaidenHTTPD directory traversal");
 desc["english"] = "
The remote host is running a version of RaidenHTTPD which is 
vulnerable to a remote directory traversal bug.  An attacker
exploiting this bug would be able to gain access to potentially 
confidential material outside of the web root.

Solution: Upgrade to RaidenHTTPD version 1.1.31
Risk factor : High";

 script_description(english:desc["english"]);
 script_summary(english:"RaidenHTTPD directory traversal");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses", francais:"Abus de CGI");
 script_copyright(english:"This script is Copyright (C) 2005 David Maciejak");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if (! get_port_state(port) ) exit(0);

banner = get_http_banner(port:port);
# Server: RaidenHTTPD/1.1.31 (Shareware)
if ( ! banner  || "RaidenHTTP" >!< banner ) exit(0);


res1 = http_keepalive_send_recv(data:http_get(item:"windows/system.ini", port:port), port:port);
res2 = http_keepalive_send_recv(data:http_get(item:"winnt/system.ini", port:port), port:port);

if ("[drivers]" >< tolower(res1) ||
    "[drivers]" >< tolower(res2)) {
		security_hole(port);
		exit(0);
}
