#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
#  This script is released under the GNU GPL v2
#

if(description)
{
 script_id(15615);
 script_version("$Revision: 1.1 $");
 
 name["english"] = "McAfee IntruShield management console";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running the McAfee IntruShield Management
Console.

If an attacker can log into it, he will have the ability to
modify sensors configuration.

Solution : Configure your firewall to prevent unauthorized hosts from
connecting to this port

Risk factor : Low";

 script_description(english:desc["english"]);
 
 summary["english"] = "Detect McAfee IntruShield management console";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 family["english"] = "General";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports(80,443);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

req = http_get(item:"/intruvert/jsp/admin/Login.jsp", port:port);
r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
if( r == NULL )exit(0);
if (egrep(pattern:"Copyright (c) 2001 by Intruvert Network Inc\.All rights Reserved\..*<TITLE>IntruShield Login</TITLE>", string:r))
{
  security_warning(port);
}
exit(0);
