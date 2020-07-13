# Written by Michel Arboi <mikhail@nessus.org>
# GPL
# 

if(description)
{
 script_id(18393);
 script_version ("$Revision: 1.3 $");
 desc = "
The Entropy Gathering Daemon is running on this port.
EGD is a user space random generator for operating systems 
that lack /dev/random

See http://egd.sourceforge.net/

Risk factor: Low";

 script_name(english: "EGD detection");
 script_description(english:desc);
 script_summary(english: "Detect the ENtrop Gathering Daemon (EGD)");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005 Michel Arboi");
 script_family(english: "Service detection");
 script_require_ports("Services/unknown");
 script_dependencies("find_service1.nasl", "find_service2.nasl");
 script_require_keys("Settings/ThoroughTests");
 exit(0);
}

#
include('global_settings.inc');
include('misc_func.inc');

if ( ! thorough_tests ) exit(0);

port = get_kb_item("Services/unknown");

if (! get_port_state(port)) exit(0);

if (get_kb_item('FindService/tcp/'+port+'/spontaneous') ||
    get_kb_item('FindService/tcp/'+port+'/get_http') ||
    get_kb_item('FindService/tcp/'+port+'/help') )
 exit(0);

s = open_sock_tcp(port);
if (! s) exit(0);
send(socket: s, data: '\0');	# get
r = recv(socket: s, length: 16);
close(s);
if (strlen(r) != 4) exit(0);
entropy = 0;
for (i = 0; i <= 3; i ++)
 entropy = (entropy << 8) | ord(r[i]);

debug_print('entropy=', entropy, '\n');

s = open_sock_tcp(port);
if (! s) exit(0);
send(socket: s, data: '\x01\x07');	# Read 7 bytes of entropy
r = recv(socket: s, length: 16);
close(s);
n = ord(r[0]);
if (strlen(r) != n + 1) exit(0);
debug_print('EGD gave ', n, 'bytes of entropy (7 requested)\n');

register_service(port: port, proto: 'egd');
