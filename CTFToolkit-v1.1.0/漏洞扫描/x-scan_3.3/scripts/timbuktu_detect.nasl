#
# (C) Tenable Network Security
#



if(description)
{
  script_id(15891);
  script_version ("$Revision: 1.5 $");
 
  script_name(english:"Timbuktu Detection");
 
  desc["english"] = "
Timbuktu Pro seems to be running on this port. 

Timbuktu Pro can allow a remote user to take the control of this system
(like the Terminal Services under Windows).

See also : http://www.netopia.com
Solution : Make sure to use strong passwords, disable this service if you do not use it
Risk factor : None";



  script_description(english:desc["english"]);
 
  summary["english"] = "Detect Timbuktu";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
  script_family(english:"Service detection");
  script_dependencie("find_service2.nasl");
  script_require_ports("Services/unknown", 407);
  exit(0);
}

include('global_settings.inc');

if ( thorough_tests )
{
port = get_kb_item("Services/unknown");
if ( ! port ) port = 407;
}
else port = 407;

if ( ! get_port_state(port) ) exit(0);

soc = open_sock_tcp(port);
if ( ! soc ) exit(0);

send(socket:soc, data:raw_string(0x00, 0x01, 0x00, 0x00, 0x00, 0x10, 0x00, 0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00));

data = recv(socket:soc, length:6);
if ( strlen(data) == 6 && ord(data[0]) == 1 && ord(data[1]) == 1 ) 
 	{
	length = ord(data[5]);
	data = recv(socket:soc, length:length);
	if ( strlen(data) != length ) exit(0);
	#length = ord(data[38]);
	#if ( length + 39 >= strlen(data) ) exit(0);
	#hostname = substr(data, 39, 39 + length - 1);
 	security_note ( port );
	}
