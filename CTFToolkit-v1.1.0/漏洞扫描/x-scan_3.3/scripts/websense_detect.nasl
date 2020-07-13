#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  This script is released under the GNU GPL v2
#
if(description)
{
 script_id(18177);
 script_version("$Revision: 1.2 $");
 
 name["english"] = "Websense reporting console detection";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host appears to be running Websense, connections are allowed 
to the web reporting console.

Letting attackers know that you are using this software will help them 
to focus their attack or will make them change their strategy.

Solution : Filter incoming traffic to this port
Risk factor : Low";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for Websense reporting console";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
  
 script_copyright(english:"This script is Copyright (C) 2005 David Maciejak");
 
 family["english"] = "Misc.";
 family["francais"] = "Divers";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("http_version.nasl");

 script_require_ports(8010);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = 8010;
if (get_port_state(port))
{
 req = http_get(item:"/Websense/cgi-bin/WsCgiLogin.exe", port:port);
 rep = http_keepalive_send_recv(port:port, data:req);
 if( rep == NULL ) exit(0);

 if ("<title>Websense Enterprise - Log On</title>" >< rep)
 {
	security_note(port);
 }
}
exit(0);
