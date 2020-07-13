# This script was written by Michel Arboi <mikhail@nessus.org>
# It is released under the GNU Public Licence.

if(description)
{
 script_id(17975);
 script_version ("$Revision: 1.25 $");
 
 name["english"] = "Identifies unknown services with GET";
 script_name(english:name["english"]);
 
 desc["english"] = "
This plugin is a complement of find_service.nes
It recognizes more banners and use an HTTP request if necessary.
 
Risk factor : Low";


 script_description(english:desc["english"]);
 
 summary["english"] = "Sends 'GET' to unknown services and look at the answer";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO); 
 script_timeout(0);
 script_copyright(english:"This script is Copyright (C) 2005 Michel Arboi");
 script_family(english: "Service detection");
 script_dependencie("find_service.nes");
# Do *not* add a port dependency  on "Services/unknown"
# Some scripts must run after this script even if there are no
# unknown services
 exit(0);
}

#
include("misc_func.inc");
include("global_settings.inc");

port = get_kb_item("Services/unknown");
if (! port) exit(0);
if (! get_port_state(port)) exit(0);
if (known_service(port: port)) exit(0);

# If the service displays a banner on connection, find_service.c does not
# send a GET request. However, if a GET request was sent and the service
# remains silent, the get_http KB entry is void

r0 = get_kb_item('FindService/tcp/'+port+'/spontaneous');	# Banner?
get_sent = 1;
if (strlen(r0) > 0)	# We have a spontaneous banner
{
 get_sent = 0;	# spontaneous banner => no GET request was sent by find_service

######## Updates for "spontaneous" banners ########

if (r0 =~ '^[0-9]+ *, *[0-9]+ *: *USERID *: *UNIX *: *[a-z0-9]+')
{
 debug_print('Fake IDENTD found on port ', port, '\n');
 register_service(port: port, proto: 'fake-identd');
 set_kb_item(name: 'fake_identd/'+port, value: TRUE);
 exit(0);
}

if (match(string: r0, pattern: 'CIMD2-A ConnectionInfo: SessionId = * PortId = *Time = * AccessType = TCPIP_SOCKET PIN = *'))
{
 report_service(port: port, svc: 'smsc');
 exit(0);
}

# 00: 57 65 64 20 4a 75 6c 20 30 36 20 31 37 3a 34 37 Wed Jul 06 17:47
# 10: 3a 35 38 20 4d 45 54 44 53 54 20 32 30 30 35 0d :58 METDST 2005.
# 20: 0a . 

if (ereg(pattern:"^(Mon|Tue|Wed|Thu|Fri|Sat|Sun|Lun|Mar|Mer|Jeu|Ven|Sam|Dim) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|D[eé]c|F[eé]v|Avr|Mai|Ao[uû]) *(0?[0-9]|[1-3][0-9]) [0-9]+:[0-9]+(:[0-9]+)?( *[ap]m)?( +[A-Z]+)? [1-2][0-9][0-9][0-9].?.?$", string:r))
{
 report_service(port: port, svc: 'daytime');
 exit(0);
}

# Possible outputs:
# |/dev/hdh|Maxtor 6Y160P0|38|C|
# |/dev/hda|ST3160021A|UNK|*||/dev/hdc|???|ERR|*||/dev/hdg|Maxtor 6B200P0|UNK|*||/dev/hdh|Maxtor 6Y160P0|38|C|
if (r0 =~ '^(\\|/dev/[a-z0-9/-]+\\|[^|]*\\|[^|]*\\|[^|]\\|)+$')
{
 report_service(port: port, svc: 'hddtemp'); 
 exit(0); 
}

# General case should be handled by find_service_3digits
if (match(string: r0, pattern: '200 CommuniGatePro PWD Server * ready*'))
{
 report_service(port: port, svc: 'pop3pw');
 exit(0);
}

# Should be handled by find_service already
if (r0 =~ "^RFB [0-9]")
{
  report_service(port:port, svc: "vnc");
  exit(0);
}
}	# else: no spontaneous banner

###################################################

k = 'FindService/tcp/'+port+'/get_http';
r = get_kb_item(k+'Hex');
if (strlen(r) > 0) r = hex2raw(s: r);
else r = get_kb_item(k);

if (strlen(r) == 0)
{
 if (get_sent			# Service did not anwer to GET
     && ! thorough_tests)	# We try again in "thorough tests"
  exit(0);

 soc = open_sock_tcp(port);
 if (! soc) exit(0);
 send(socket: soc, data: 'GET / HTTP/1.0\r\n\r\n');
 r = recv(socket:soc, length:4096);
 close(soc);
 if (! r)
 {
   debug_print('Service on port ', port, ' does not answer to "GET / HTTP/1.0"\n');
   exit(0);
 }
 set_kb_item(name: k, value: r);
 if ('\0' >< r) set_kb_item(name: k + 'Hex', value: hexstr(r));
}

# aka HTTP/0.9
if (r =~ '^[ \t\r\n]*<HTML>.*</HTML>')
{
 report_service(port: port, svc: 'www', banner: r);
 exit(0);
}

if (r == '[TS]\r\n')
{
 report_service(port: port, svc: 'teamspeak-tcpquery', banner: r);
 exit(0);
}

if (r == 'gethostbyaddr: Error 0\n')
{
 register_service(port:port, proto:"veritas-netbackup-client");
 security_note(port:port, data:"Veritas NetBackup Client Service is running on this port");
 exit(0);
}

if ("GET / HTTP/1.0 : ERROR : INVALID-PORT" >< r)
{
 report_service(port: port, svc: 'auth', banner: r);
 exit(0);
}

if ('Host' >< r && 'is not allowed to connect to this MySQL server' >< r)
{
 register_service(port: port, proto: 'mysql');	# or wrapped?
 security_note(port: port, data: 
"A MySQL server seems to be running on this port but it
rejects connection from the Nessus scanner.");
  exit(0);
}

# Taken from find_service2
if (strlen(r) == 3 && (r[2] == '\x10'||	# same test as find_service
                       r[2] == '\x0b') ||
    r == '\x78\x01\x07' || r == '\x10\x73\x0A' || r == '\x78\x01\x07' ||
    r == '\x08\x40\x0c' )
{
  register_service(port: port, proto: "msdtc");
  security_note(port: port, data: "A MSDTC server seems to be running on this port");
  exit(0);
}

#### Double check: all this should be handled by find_service.nes ####

if (r == 'GET / HTTP/1.0\r\n\r\n')
{
 report_service(port: port, svc: 'echo', banner: r);
 exit(0);
}

# Should we excluded port=5000...? (see find_service.c)
if (r =~ '^HTTP/1\\.[01] +[1-5][0-9][0-9] ')
{
 report_service(port: port, svc: 'www', banner: r);
 exit(0); 
}

# Suspicious: "3 digits" should appear in the banner, not in response to GET
if (r =~ '^[0-9][0-9][0-9]-?[ \t]')
{
 debug_print('"3 digits" found on port ', port, ' in response to GET\n');
 register_service(port: port, proto: 'three_digits');
 exit(0); 
}

if (r =~ "^RFB [0-9]")
{
  report_service(port:port, svc: "vnc");
  exit(0);
}
