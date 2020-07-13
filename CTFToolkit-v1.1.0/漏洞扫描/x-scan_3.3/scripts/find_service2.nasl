#
# This script was written by Michel Arboi <arboi@alussinan.org>
#
# It is released under the GNU Public Licence.
#
#

if(description)
{
 script_id(11153);
 script_version ("$Revision: 1.156 $");
 
 name["english"] = "Identifies unknown services with 'HELP'";
 name["francais"] = "Identifie les services inconnus avec 'HELP'";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
This plugin is a complement of find_service.nes
It sends a HELP request to the remaining unknown services
and tries to identify them.

Risk factor : Low";


 desc["francais"] = "
Ce plugin est un complément de find_service.nes
Il envoie une requête HELP aux services qui restent inconnus et
essaie de les identifier.

Facteur de risque : Faible";

 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Sends 'HELP' to unknown services and look at the answer";
 summary["francais"] = "Envoie 'HELP' aux services inconnus et observe la réponse";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO); 
 script_timeout(0);
 script_copyright(english:"This script is Copyright (C) 2002 Michel Arboi",
		francais:"Ce script est Copyright (C) 2002 Michel Arboi");
 script_family(english: "Service detection");
 script_dependencie("find_service.nes", "find_service_3digits.nasl", "rpcinfo.nasl", "dcetest.nasl", "apache_SSL_complain.nasl");
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

# Check only mute services?
# r0 = get_unknown_banner(port: port, dontfetch: 1);
# if (r0) exit(0);

soc = open_sock_tcp(port);
if (! soc) exit(0);

send(socket: soc, data: 'HELP\r\n');
r = recv(socket:soc, length:4096);
close(soc);

if (!r)
{
  # Mute service
  debug_print('service on port ', port, ' does not answer to "HELP"\n');
  # security_note(port: port, data: "A mute service is running on this port");
  # jwl TODO:  set kb here and come back and reap the mute services in separate script
  exit(0);
}

set_kb_item(name: 'FindService/tcp/'+port+'/help', value: r);

# The full banner is (without end of line:
# ( success ( 1 2 ( ANONYMOUS ) ( edit-pipeline ) ) )
if ( "success ( 1 2"  >< r ) 
{
 register_service(port:port, proto:"subversion");
 security_note(port:port, data:"A SubVersion server is running on this port");
 exit(0);
}

# [root@f00dikator new_nasl_mods]# telnet 10.10.10.7 7110
# Trying 10.10.10.7...
# Connected to 10.10.10.7.
# Escape character is '^]'.
# hash 30026                              <------- Server
# yo there my brother from another mother <------- Client
# error NOT AUTHORIZED YET                <------- Server 

if ("error NOT AUTHORIZED YET" >< r)
{
 register_service(port:port, proto:"DMAIL_Admin");
 security_note(port:port, data:"The remote host is running a DMAIL Administrative service on this port");
 exit(0);
}


if ( "From Server : MESSAGE RECEIVED" >< r)
{
 register_service(port:port, proto:"shixxnote");
 security_note(port:port, data:"A shixxnote server is running on this port");
 exit(0);
}


# xmlns='jabber:client' xmlns:
# submitted by JYoung ~at- intramedplus.com 
if ( "xmlns='jabber:client'" >< r)
{
 register_service(port:port, proto:"ejabberd");
 security_note(port:port, data:"An ejabberd server is running on this port");
 exit(0);
}

if ( "Request with malformed data; connection closed" >< r )
{
 register_service(port:port, proto:"moodle-chat-daemom");
 security_note(port:port, data:"A Moodle Chat Daemon is running on this port");
 exit(0);
}

if (r =~ '^0\\.[67]\\.[0-9] LOG\0 {16}')
{
 register_service(port: port, proto: "partimage");
 security_note(port:port, data:"Partimage is running on this port
It requires login");
 exit(0);
}

if (r =~ '^0\\.[67]\\.[0-9]\0 {16}')
{
 register_service(port: port, proto: "partimage");
 security_note(port:port, data:"Partimage is running on this port
It does not require login");
 exit(0);
}

if ("%x%s%p%nh%u%c%z%Z%t%i%e%g%f%a%C" >< r )
{
 register_service(port:port, proto:"egcd");
 security_note(port:port, data:"egcd is running on this port");
 exit(0);
}

if ( "f6ffff10" >< hexstr(r) && strlen(r) < 6 )
{
 register_service(port:port, proto:"BackupExec");
 security_note(port:port, data:"A BackupExec Agent is running on this port");
 exit(0);
}

if ('UNKNOWN COMMAND\n' >< r )
{
 register_service(port:port, proto:"clamd");
 security_note(port:port, data:"A clamd daemon (part of ClamAntivirus) is running on this port");
 exit(0);
}

if ( "AdsGone 200" >< r && "HTML Ad" >< r )
{
 register_service(port:port, proto:"AdsGone");
 security_note(port:port, data:"An AdsGone proxy server is running on this port");
 exit(0);
}

if (egrep(pattern:"^Centra AudioServer", string:r) )
{
 register_service(port:port, proto:"centra");
 security_note(port:port, data:"A Centra audio server is running on this port");
 exit(0);
}

# TenFour TFS Secure Messaging Server, not RFC compliant
if ('Ok\r\n500 Command unknown' >< r )
{
 register_service(port:port, proto:"smtp");
 security_note(port:port, data:"A SMTP server is running on this port");
 exit(0);
}

if ("VERIFY = F$VERIFY" >< r || # Multinet 4.4 Imap daemon...
    "* OK dovecot ready." >< r )
{
 register_service(port:port, proto:"imap");
 security_note(port:port, data:"An IMAP server is running on this port");
 exit(0);
}


if ("421 Server is temporarily unavailable - pleast try again later" >< r &&
    "421 Service closing control connection" >< r)
{
 register_service(port:port, proto:"ftp-disabled");
 security_note(port:port, data:"A (disabled) FTP server is running on this port");
 exit(0);
}


if ("RSTP/1.0 505 RSTP Version not supported" >< r )
{
 register_service(port:port, proto:"rtsp");
 security_note(port:port, data:"A RSTP (shoutcast) server is running on this port");
 exit(0);
}


if ("ERR INVALID-ARGUMENT" >< r &&
    "ERR UNKNOWN-COMMAND" >< r )
{
 register_service(port:port, proto:"nut");
 security_note(port:port, data:"A Network UPS Tool (NUT) server is running on this port");
 exit(0);
}

if ('\x80\x3d\x01\x03\x01' >< r)
{
 # http://osiris.shmoo.com/
 register_service(port:port, proto:"osiris");
 security_note(port:port, data:"An Osiris daemon is running on this port");
 exit(0);
}
if ('\x15\x03\x01' == r)
{
 register_service(port:port, proto:"APC_PowerChuteBusinessEdition");
 security_note(port:port, data:"APC Power Chute Business Edition is running on this port");
 exit(0);
}

if ( 'CAP PH\r\n' >< r )
{
 register_service(port:port, proto:"BrightMail_AntiSpam");
 security_note(port:port, data:"BrightMail AntiSpam is running on this port");
 exit(0);
}
if ('\xea\xdd\xbe\xef' >< r)
{
 register_service(port:port, proto:"veritas-netbackup-client");
 security_note(port:port, data:"Veritas NetBackup Client Service is running on this port");
 exit(0);
}

# http://www.cisco.com/en/US/products/sw/voicesw/ps556/products_tech_note09186a00801a62b9.shtml#topic1
if ('\x70\x5f\x0a\x10\x01' >< r)
{
 register_service(port:port, proto:"cisco-ris-data-collector");
 security_note(port:port, data:"A CISCO RIS Data Collector is running on this port");
 exit(0);
}


if ("Hello, this is quagga" >< r )
{
 register_service(port:port, proto:"quagga");
 security_note(port:port, data:"The quagga daemon is listening on this port");
 exit(0);
}

if ( 'Hello\n' >< r )
{
 register_service(port:port, proto:"musicdaemon");
 security_note(port:port, data:"musicdaemon is listening on this port");
 exit(0);
}



if (egrep(pattern:"^220.*Administrator Service ready\.", string:r) ||
    egrep(pattern:"^220.*eSafe@.*Service ready", string:r))
{
 register_service(port:port, proto:"smtp");
 exit(0);
}

if ( "Integrated port" >< r && "Printer Type" >< r && "Print Job Status" >< r)
{
  # This is a "fake" finger server, showing the printer status.
  # see bug#496
 register_service(port:port, proto:"finger-lexmark");
 exit(0);
}


if ("Invalid password!!!" >< r || 
    "Incorrect password!!!" >< r )
{
 register_service(port:port, proto:"wollf");
 security_note(port:port, data:"A Wollf backdoor is running on this port");
 exit(0);
}

if ("version report" >< r )
{
 register_service(port:port, proto:"gnocatan");
 security_note(port:port, data:"A gnocatan game server is running on this port");
 exit(0);
}

if ("Welcome on mldonkey command-line" >< r)
{
 register_service(port:port, proto:"mldonkey-telnet");
 security_note(port:port, data:"A MLdonkey telnet interface is running on this port");
 exit(0);
}

if ( egrep(pattern:"^connected\. .*, version:", string:r) )
{
 register_service(port:port, proto:"subseven");
 security_note(port:port, data:"A subseven backdoor is running on this port");
 exit(0);
}


if ( egrep(pattern:"^220 Bot Server", string:r) ||
     '\xb0\x3e\xc3\x77\x4d\x5a\x90' >< r )
{
 register_service(port:port, proto:"agobot.fo");
 security_note(port:port, data:"An Agobot.fo backdoor is running on this port");
 exit(0);
}


if ( "RemoteNC Control Password:" >< r )
{
 register_service(port:port, proto:"RemoteNC");
 security_note(port:port, data:"A RemoteNC console is running on this port");
 exit(0);
}

if ( "Sensor Console Password:" >< r )
{
 register_service(port:port, proto:"fluxay");
 security_note(port:port, data:"A fluxay sensor is running on this port");
 exit(0);
}

if ('\x3c\x65\x72\x72\x6f\x72\x3e\x0a' >< r)
{
 register_service(port:port, proto:"gkrellmd");
 security_note(port:port, data:"A gkrellmd system monitor daemon is running on this port");
 exit(0);
}
 
# QMTP / QMQP
if (r =~ '^[1-9][0-9]*:[KZD]')
{
  register_service(port: port, proto: "QMTP");
  security_note(port: port, data: "A QMTP / QMQP server is running on this port");
}

# BZFlag Server (a game on SGI)
if (r =~ '^BZFS')
{
 register_service(port:port, proto:"bzfs");
 security_note(port:port, data:"A BZFlag game server seems to be running on this port");
 exit(0);
}

# (Solaris) lpd server
if(ereg(pattern: "^Invalid protocol request.*:HHELP.*", string:r))
{
 register_service(port:port, proto:"lpd");
 security_note(port:port, data:"An LPD server seems to be running on this port");
 exit(0);
}

if (strlen(r) == 4 && '\x3d\x15\x1a\x3d' >< r)
{
 register_service(port:port, proto:"hacker_defender");
 security_note(port:port, data:"An 'Hacker Defender' backdoor seems to be running on this port");
 exit(0);
}

# http://hea-www.harvard.edu/RD/ds9/
if ("XPA$ERROR unknown xpans request:" >< r )
{
 register_service(port:port, proto:"DS9");
 security_note(port:port, data:'A DS9 service seems to be running on this port\nSee also : http://hea-www.harvard.edu/RD/ds9/');
 exit(0);
}

if ('421 Unauthorized connection to server\n' >< r )
{
 register_service(port:port, proto:"ncic");
 security_note(port:port, data:"A NCIC service seems to be running on this port");
 exit(0);
}

if ( strlen(r) == 4 && '\x09\x50\x09\x50' ><  r)
{
 register_service(port:port, proto:"dell_management_client");
 security_note(port:port, data:"A Dell Management client seems to be running on this port");
 exit(0);
}

if ( "gdm already running. Aborting!" >< r )
{
 register_service(port:port, proto:"xdmcp");
 security_note(port:port, data:"An xdmcp server seems to be running on this port");
 exit(0);
}

if ( strlen(r) == strlen("20040616105304") &&
      ereg(pattern:"200[0-9][01][0-9][0-3][0-9][0-2][0-9][0-5][0-9][0-5][0-9]$",
	   string:r))
 {
 register_service(port:port, proto:"LPTOne");
 security_note(port:port, data:"A LPTOne server seems to be running on this port");
 exit(0);
}

if ('ERROR Not authenticated\n' >< r )
{
 register_service(port:port, proto:"hpjfpmd");
 security_note(port:port, data:"An HP WebJetAdmin server seems to be running on this port");
 exit(0);
}

if ( "500 P-Error" >< r && "220 Hello" >< r )
{
 register_service(port:port, proto:"unknown_irc_bot");
 security_note(port:port, data:"An IRC bot seems to be running on this port");
 exit(0);
}

if ( "220 WinSock" >< r )
{
 register_service(port:port, proto:"winsock");
 security_note(port:port, data:"A WinSock server seems to be running on this port");
 exit(0);
}

if ( "DeltaUPS:" >< r )
{
 register_service(port:port, proto:"delta-ups");
 security_note(port:port, data:"A DeltaUPS monitoring server seems to be running on this port");
 exit(0);
}

if ( ereg(pattern:"lpd: .*", string:r) )
{
 register_service(port:port, proto:"lpd");
 security_note(port:port, data:"An LPD server seems to be running on this port");
 exit(0);
}

if(ereg(pattern: "^/usr/sbin/lpd.*", string:r))
{
 register_service(port:port, proto:"lpd");
 security_note(port:port, data:"An LPD server seems to be running on this port");
 exit(0);
}

if ( "<!doctype html" >< tolower(r) ) 
{
 register_service(port:port, proto:"www");
 security_note(port:port, data:"A (non-RFC compliant) web server seems to be running on this port");
 exit(0);
}
if("An lpd test connection was completed" >< r || 
    "Bad from address." >< r || 
    "your host does not have line printer access" >< r ||
    "does not have access to remote printer" >< r )
{
 register_service(port:port, proto:"lpd");
 security_note(port:port, data:"An LPD server seems to be running on this port");
 exit(0);
}

# PPR
if (r =~ "^lprsrv: unrecognized command:")
{
  register_service(port:port, proto:"lpd");
  security_note(port:port, data:"PPR seems to be running on this port");
  exit(0);
}

if(ereg(pattern:"^login: Password: (Login incorrect\.)?$", string:r) ||
   ereg(pattern:"^login: Login incorrect\.", string:r))
{
 register_service(port:port, proto:"uucp");
 security_note(port:port, data:"An UUCP daemon seems to be running on this port");
 exit(0);
}
if(ereg(pattern:"^login: Login incorrect\.$", string:r))
{
 register_service(port:port, proto:"uucp");
 security_note(port:port, data:"An UUCP daemon seems to be running on this port");
 exit(0);
}

# IRC server
if (ereg(pattern: "^:.* 451 .*:", string:r))
{
  register_service(port: port, proto: "irc");
  security_note(port: port, data: "An IRC server seems to be running on this port");
  exit(0);
}

if(ereg(pattern:"^(Mon|Tue|Wed|Thu|Fri|Sat|Sun|Lun|Mar|Mer|Jeu|Ven|Sam|Dim) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|D[eé]c|F[eé]v|Avr|Mai|Ao[uû]) *(0?[0-9]|[1-3][0-9]) [0-9]+:[0-9]+(:[0-9]+)?( *[ap]m)?( +[A-Z]+)? [1-2][0-9][0-9][0-9].?.?$",
        string:r) ||
   ereg(pattern:"^[0-9][0-9] +(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|D[eé]c|F[eé]v|Avr|Mai|Ao[uû]) +[1-2][0-9][0-9][0-9] +[0-9]+:[0-9]+:[0-9]+( *[ap]m)? [A-Z0-9]+.?.?$", string:r, icase: 1) ||
   r =~ '^(0?[0-9]|[1-2][0-9]|3[01])-(0[1-9]|1[0-2])-20[0-9][0-9][\r\n]*$' ||
   r =~ '^([01]?[0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9] (19|20)[0-9][0-9]-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])[ \t\r\n]*$' ||
   ereg(pattern:"^(Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday), (January|February|March|April|May|June|July|August|September|October|November|December) ([0-9]|[1-3][0-9]), [1-2][0-9][0-9][0-9] .*", string:r) ||
# MS flavor of daytime
   ereg(pattern:"^[0-9][0-9]?:[0-9][0-9]:[0-9][0-9] [AP]M [0-9][0-9]?/[0-9][0-9]?/[0-2][0-9][0-9][0-9].*$", string:r) ||
   r =~ '^([01]?[0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9] +(0?[1-9]|[12][0-9]|3[01])/(0?[1-9]|1[0-2]|3[01])/(19|20)[0-9][0-9][ \t\r\n]*$' )
{
  register_service(port:port, proto:"daytime");
  security_note(port: port, data: "Daytime is running on this port");
  exit(0);
}

# Banner:
# HP OpenView OmniBack II A.03.10:INET, internal build 325, built on Mon Aug 23 15:50:58 1999. 
if (match(string: r, pattern: "HP OpenView OmniBack II*"))
{
  register_service(port: port, proto: "omniback");
  security_note(port: port, data: "HP Omniback seems to be running on this port");
  exit(0);
}

# Banner:
# HP OpenView Storage Data Protector A.05.00: INET, internal build 190, built on Tue Jul 16 17:37:32 2002.
if (match(string: r, pattern: "HP OpenView Storage Data Protector"))
{
  register_service(port: port, proto: "hpov-storage");
  security_note(port: port, data: "HP OpenView Storage Data Protector seems to be running on this port");
  exit(0);
}

# Veritas Netbackup
if (r =~ '^1000 +2\n43\nunexpected message received' ||
    "gethostbyaddr: No such file or directory" >< r )
{
  register_service(port: port, proto: "netbackup");
  security_note(port: port, data: "Veritas Netbackup seems to be running on this port");
  exit(0);
}

# Veritas Backup Exec Remote Agent (6103/tcp)
if (r == '\xf6\xff\xff\xff\x10')
{
  register_service(port: port, proto: "backup_exec");
  security_note(port: port, data: "Veritas Backup Exec Remote Agent seems to be running on this port");
  exit(0);
}

# BMC Patrol
if (r == "SDPACK")
{
  register_service(port: port, proto: "bmc-perf-sd");
  security_note(port: port, data: "BMC Perform Service Daemon seems to be running on this port");
  exit(0);
}

# SNPP
if (r =~ '^220 .* SNPP ' || egrep(string: r, pattern: '^214 .*PAGE'))
{
  register_service(port: port, proto: "snpp");
  security_note(port: port, data: "A SNPP server seems to be running on this port");
  exit(0);
}

# HylaFax FTP
if (egrep(string: r, pattern: '^214-? ') && 'MDMFMT' >< r)
{
  register_service(port: port, proto: "hylafax-ftp");
  security_note(port: port, data: "A HylaFax server seems to be running on this port");
  exit(0);
}


# HylaFAX  (hylafax spp?)
if ( egrep(string:r, pattern:"^220.*HylaFAX .*Version.*") )
{
  register_service(port: port, proto: "hylafax");
  security_note(port: port, data: "A HylaFax server seems to be running on this port");
  exit(0);
}


if ( egrep (string:r, pattern:"^S: FTGate [0-9]+\.[0-9]+") )
{
  register_service(port: port, proto: "ftgate-monitor");
  security_note(port: port, data: "A FTGate Monitor server seems to be running on this port");
  exit(0);
} 

# IRCn
if (strlen(r) == 2048 && r =~ '^[ ,;:.@$#%+HMX\n-]+$' && '-;;=' >< r &&
	'.;M####+' >< r && '.+ .%########' >< r && ':%.%#########@' >< r)
{
  register_service(port: port, proto: 'IRCn-finger');
  security_note(port: port, data: "IRCn finger service seems to be running on this port");
  exit(0);
}

if ("Melange Chat Server" >< r)
{
  register_service(port: port, proto: 'melange-chat');
  security_note(port: port, data: "Melange Chat Server is running on this port");
  exit(0);
}

# http://www.directupdate.net/
if (r =~ '^OK Welcome .*DirectUpdate server')
{
  register_service(port: port, proto: 'directupdate');
  security_note(port: port, data: "A DirectUpdate server is running on this port");
  exit(0);
}

# http://www.xboxmediaplayer.de

if (r == "HELLO XBOX!")
{
  register_service(port: port, proto: 'xns');
  security_note(port: port, data: "A XNS streaming server seems to be running on this port");
  exit(0);
}

# Windows 2000 BackupExec

if (r == '\xf6\xff\xff\xff\x10')
{
  register_service(port: port, proto: "backupexec");
  security_note(port: port, data: "A BackupExec server seems to be running on this port");
  exit(0);
}

# SAP/DB niserver (default port = 7269)
# 0000 4c 00 00 00 03 ff 00 00 ff ff ff ff ff ff ff ff
# 0020 01 00 04 00 4c 00 00 00 00 02 34 00 ff 0d 00 00
# 0040 ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
# 0060 00 00 00 00 2e 0f 13 40 00 00 00 00 89 74 09 08
# 0100 05 49 2d 31 00 04 50 ff ff 03 52 01

if (substr(r, 0, 15) == hex2raw(s: "4c00000003ff0000ffffffffffffffff"))
{
  register_service(port: port, proto: "sap_db_niserver");
  security_note(port: port, data: "SAP/DB niserver seems to be running on this port");
  exit(0);
}

# Submitted by Lyal Collins
# 00: 01 09 d0 02 ff ff 01 03 12 4c .. . ...L
# DB2 V6 and possibly Db2 V7, running on zOS - TCP ports 446 and 448
if (r == '\x01\x09\xD0\x02\xFF\xFF\x01\x03\x12\x4C')
{
  register_service(port: port, proto: "db2");
  security_note(port: port, data: "DB2 is running on this port");
  exit(0);
}

# Checkpoint FW-1 Client Authentication (TCP/259)
# 00: 43 68 65 63 6b 20 50 6f 69 6e 74 20 46 69 72 65 Check Point Fire
# 10: 57 61 6c 6c 2d 31 20 43 6c 69 65 6e 74 20 41 75 Wall-1 Client Au
# 20: 74 68 65 6e 74 69 63 61 74 69 6f 6e 20 53 65 72 thentication Ser
# 30: 76 65 72 20 72 75 6e 6e 69 6e 67 20 6f 6e 20 67 ver running on g
# 40: 61 74 65 6b 65 65 70 65 72 30 31 2e 6b 61 69 73 atekeeper01.kais
# 50: 65 72 6b 72 61 66 74 2e 64 65 0d 0a 0d ff fb 01 erkraft.de... .
# 60: ff fe 01 ff fb 03 55 73 65 72 3a 20 47 45 54 20 . .User: GET
# 70: 2f 20 48 54 54 50 2f 31 2e 30 0d 0a 55 73 65 72 / HTTP/1.0..User
# 80: 20 47 45 54 20 2f 20 48 54 54 50 2f 31 2e 30 20 GET / HTTP/1.0
# 90: 6e 6f 74 20 66 6f 75 6e 64 0d 0a 0d 0d 0a 55 73 not found.....Us
# a0: 65 72 3a 20 er: 

if ("Check Point FireWall-1 Client Authentication Server" >< r)
{
  register_service(port: port, proto: "fw1_client_auth");
  security_note(port: port, data: "Checkpoint Firewall-1 Client Authentication Server seems to be running on this port");
  exit(0);
}

if (r =~ "^200 .* (PWD Server|poppassd)")
{
  register_service(port: port, proto: "poppassd");
  security_note(port: port, data: "A poppassd server seems to be running on this port");
  exit(0);
}

# Ebola antivirus

if ("Welcome to Ebola " >< r )
{
 register_service( port : port, proto: "ebola" );
 set_kb_item(name:"ebola/banner/" + port, value: r );
 security_note(port : port, data: "An Ebola server is running on this port :\n" + r );
 exit(0);
}

# www.midas.org
if (r =~ '^MIDASd v[2-9.]+[a-z]? connection accepted')
{
  register_service(port: port, proto: 'midas');
  security_note(port: port, data: "A MIDAS server is running on this port");
  exit(0);
}

# Crystal Reports
if (r =~ '^server [0-9.]+ connections: [0-9]+')
{
  register_service(port: port, proto: 'crystal');
  security_note(port: port, data: 'Crystal Reports seems to be running on this port');
  exit(0);
}

# Trueweather taskbar applet
if (r =~ '^TrueWeather\r\n\r\n')
{
  register_service(port: port, proto: 'trueweather');
  security_note(port: port, data: 'TrueWeather taskbar applet is running on this port');
  exit(0);
}

# W32.IRCBot.E or W32.IRCBot.F or W32.Randex or W32.Korgo.V
if (r == '220 \r\n331 \r\n230 \r\n')
{
  register_service(port: port, proto: 'ircbot');
  security_note(port: port, data: 'A W32.IRCBot backdoor is running on this port');
  exit(0);
}

if (ereg(string: r, pattern: "^RTSP/1\.0 "))
{
  register_service(port: port, proto: 'rtsp');
  security_note(port: port, data: "A streaming server is running on this port");
  exit(0);
}

# BMC's ECS product (part of Control-M) gateway listener
# 00: 61 20 30 30 30 30 30 30 32 64 47 52 30 39 33 32    a 0000002dGR0932
# 10: 30 30 30 30 39 30 43 47 47 41 54 45 57 41 59 20    000090CGGATEWAY 
# 20: 30 43 47 55 31 30 30 33 31 30 30 36 30 43 47 5f    0CGU100310060CG_
# 30: 41 20 32 32 31 47 41                               A 221GA
if (r =~ '^a [0-9a-zA-Z]+GATEWAY [0-9A-Z]+_A [0-9A-Z]+')
{
  register_service(port: port, proto: 'ctrlm-ecs-gateway');
  security_note(port: port, data: "An ECS gateway listener (par of Control-M) is running on this port");
  exit(0);
}

# Running on 400/tcp?!
if (r == '\xDE\xAD\xF0\x0D')
{
  register_service(port: port, proto: 'jwalk');
  security_note(port: port, data: "A Seagull JWalk server is running on this port");
  exit(0);
}

# Contributed by Thomas Reinke - running on TCP/23
# Interface to ADSL router smc7204BRB 
if ("CONEXANT SYSTEMS, INC" >< r && "ACCESS RUNNER ADSL CONSOLE PORT" >< r 
    && "LOGON PASSWORD" >< r)
{
  register_service(port: port, proto: 'conexant-admin');
  security_hole(port: port, data: "Interface of a Conexant ADSL router is running on this port");
  exit(0);
}

# Default port = 9090
if (r == 'GET %2F HTTP%2F1.0\n')
{
  register_service(port: port, proto: 'slimserver');
  security_hole(port: port, data: "The Slimserver streaming server (command interface)
is running on this port");
  exit(0);
}

# 00: 0d 0a 50 72 65 73 73 20 72 65 74 75 72 6e 3a 2a    ..Press return:*
# 10: 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a    ****************
# 20: 0d 0a 45 6e 74 65 72 20 50 61 73 73 77 6f 72 64    ..Enter Password
# 30: 3a 2a 0d 0a 45 6e 74 65 72 20 50 61 73 73 77 6f    :*..Enter Passwo
#  40: 72 64 3a
if ('Press return:*****************' >< r && 'Enter Password:' >< r)
{
  register_service(port: port, proto: 'darkshadow-trojan');
  security_hole(port: port, data: "The Darshadow trojan horse seems to be running on this port");
  exit(0);
}

# Contributed by David C. Shettler
# http://esupport.ca.com/index.html?/public/dto_transportit/infodocs/LI57895.asp
if (r == 'ACK')
{
  register_service(port: port, proto: 'tng-cam');
  security_hole(port: port, data: 'CA Messaging (part of Unicenter TNG) is running on this port');
  exit(0);
}

# Contributed by Jan Dreyer - unfortunately, I could not find much data on 
# this Trojan horse. It was found running on port 2400
# The banner is:
# +------------------------+
# | DllTrojan by ScriptGod |
# +------------------------+
# |       [27.04.04]       |
# +------------------------+
# enter pass:
#

if ("+------------------------+" >< r || "DllTrojan by ScriptGod" >< r)
{
  register_service(port: port, proto: 'dll-trojan');
  security_hole(port: port, data: 'A trojan horse (DllTrojan) seems to be running on this port\nClean your system!');

  exit(0);
}

# Submitted by Paul Weatherhead
if (r == '\x3d\x15\x1a\x3d')
{
  register_service(port: port, proto: 'rcserv-trojan');
  security_hole(port: port, data: 'A trojan horse (RCServ) seems to be running on this port\nYou should clean your system:\nthe executable file might be MDTC.EXE');
  exit(0);
}

if (r == 'ERROR\n')
{
  register_service(port: port, proto: 'streaming21');
  security_note(port: port, data: "A Streaming21 server seems to be running on this port");
  exit(0);
}

# Submitted by Adam Baldwin - Reference http://evilpacket.net
# Identifies Symantec ManHunt or SNS console (qsp proxy)
# 32 bytes of data sent when a connection is made
# 01 01 00 08 1C EE 01 00 00 00 00 00 00 00 00 00
# 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
if (r == '\x01\x01\x00\x08\x1c\xee\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
{
  register_service(port: port, proto: 'qsp-proxy');
  security_note(port: port, data: "A Symantec ManHunt / SNS console (QSP Proxy) seems to be running on this port");
  exit(0);
}

# sunRay Server - thanks to kent@unit.liu.se (Kent Engström)
if("ERR/InvalidCommand" >< r) 
{
 register_service(port:port, proto:"sunraySessionMgr");
 security_note(port:port, data:"sunraySessionMgr server is running on this port");
 exit(0);
}
  
# Shoutcast

if (r =~ "^ICY 401")
{
  register_service(port: port, proto: "shoutcast");
  security_note(port: port, data: "A shoutcast server seems to be running on this port");
  exit(0);
}

# NFR
if (egrep(pattern:"^Getserver 1\.0 - identify yourself", string:r ) )
{
 register_service(port:port, proto:"nfr-admin-gui");
 security_note(port:port, data:"An NFR Administrative interface is listening on this port");
 exit(0);
}

# remstats.sf.net
if ( "ERROR: unknown directive: " >< r )
{
  register_service(port:port, proto:"remstats");
  security_note(port:port, data:"A remstats service is running on this port");
  exit(0);
}

if ( "NCD X Terminal Configuration" >< r )
{
  register_service(port:port, proto:"ncdx_term_config");
  security_note(port:port, data:"A NCD X Terminal Configuration service is running on this port");
  exit(0);
}

if ("NPC Telnet permit one" >< r )
{
  register_service(port:port, proto:"telnet");
  security_note(port:port, data:"A (NPC) telnet service is running on this port");
  exit(0);
}

if ( "SiteManager Proxy" >< r )
{
  register_service(port:port, proto:"site_manager_proxy");
  security_note(port:port, data:"A Site Manager Proxy service is running on this port");
  exit(0);
}

if ( egrep(pattern:"^GPSD,.*", string:r) )
{
  register_service(port:port, proto:"gpsd");
  security_note(port:port, data:"A gpsd daemon is running on this port");
  exit(0);
}


if ( egrep(pattern:"^200.*Citadel(/UX| server ready).*", string:r) )
{
  register_service(port:port, proto:"citadel/ux");
  security_note(port:port, data:"A Citadel/UX BBS is running on this port");
  exit(0);
}

if ( "Gnome Batalla" >< r )
{
 register_service(port:port, proto:"gnome_batalla");
 security_note(port:port, data:"A Gnome Batalla service is running on this port");
  exit(0);
}
   
if ("System Status" >< r && "Uptime" >< r )
{
  register_service(port:port, proto: "systat");
  security_note(port: port, data: "The systat service is running on this port");
  exit(0);
}

if ("ESTABLISHED" >< r && "TCP" >< r)
{
  register_service(port:port, proto: "netstat");
  security_note(port: port, data: "The netstat service is running on this port");
  exit(0);
}

if ( "Charles Dickens" >< r || "George Bernard Shaw" >< r )
{
  register_service(port:port, proto: "qotd");
  security_note(port: port, data: "qotd (Quote of the Day) seems to be running on this port");
  exit(0);
}

if ("Can't locate loadable object for module" >< r && "BEGIN failed--compilation aborted" >< r )
{
  register_service(port:port, proto: "broken-perl-script");
  security_note(port: port, data: "A broken perl script is running on this port");
  exit(0);
}

if ("/usr/games/fortune: not found" >< r ||
    r =~ '^"[^"]+" *Autor desconocido[ \t\r\n]*$')
{
  register_service(port:port, proto: "qotd");
  security_note(port: port, data: "qotd (Quote of the Day) seems to be running on this port (misconfigured)");
  exit(0);
}

if ("Check Point FireWall-1 authenticated Telnet server" >< r )
{
  register_service(port:port, proto: "fw1-telnet-auth");
  security_note(port: port, data: "A Firewall-1 authenticated telnet server is running on this port");
  exit(0);
}

if ( "NOTICE AUTH : Bitlbee" >< r )
{
  register_service(port:port, proto: "irc");
  security_note(port: port, data: "An IRC server seems to be running on this port");
  exit(0);
}

if (r =~ '^sh-[0-9.]+# ')
{
  register_service(port:port, proto: "wild_shell");
  security_hole(port: port, data: "A shell seems to be running on this port ! (this is a possible backdoor)");
}

if ( ("Microsoft Windows [Version " >< r) &&
     ("(C) Copyright 1985-" >< r) &&
     ("Microsoft Corp." >< r) )
{
  register_service(port:port, proto: "wild_shell");
  security_hole(port: port, data: "A Windows shell seems to be running on this port ! (this is a possible backdoor)");
}

if ( "1|0|0||" >< r )
{
  register_service(port:port, proto: "PigeonServer");
  security_note(port: port, data: "PigeonServer seems to be running on this port");
  exit(0);
}

if (r =~ '^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+\n$')
{
 register_service(port:port, proto:"kde-lisa");
 security_note(port:port, data:"KDE Lisa server is running on this port");
 exit(0);
}

# Submitted by Lucian Ravac - See http://zabbix.org
if (r == 'ZBX_NOTSUPPORTED\n')
{
 register_service(port: port, proto: 'zabbix');
 security_note(port: port, data: 'A Zabbix agent is running on this port');
 exit(0);
}

# Submitted by Brian Spindel - Gopher on Windows NT
# 00: 33 20 2d 2d 36 20 42 61 64 20 52 65 71 75 65 73	3 --6 Bad Reques
# 10: 74 2e 20 0d 0a 2e 0d 0a 				t. 

if (r == '3 --6 Bad request. \r\n.\r\n') 
{
 register_service(port: port, proto: 'gopher');
 security_note(port: port, data: 'A Gopher server seems to be running on this port');
 exit(0);
}

# 00: 01 72 6c 6f 67 69 6e 64 3a 20 50 65 72 6d 69 73 .rlogind: Permis
# 10: 73 69 6f 6e 20 64 65 6e 69 65 64 2e 0d 0a sion denied... 

if (match(string: r, pattern: '\x01rlogind: Permission denied*', icase: 1))
{
 register_service(port: port, proto: 'rlogin');
 security_note(port: port, data: 'rlogind seems to be running on this port');
 exit(0);
}

# 00: 73 74 61 74 64 20 76 65 72 73 69 6f 6e 3a 33 2e statd version:3.
# 10: 32 20 6d 73 67 69 64 3a 32 30 30 35 2e 30 35 2e 2 msgid:2005.05.
# 20: 31 38 20 31 30 3a 35 30 3a 33 35 0d 0a 18 10:50:35..
# Note: this is *unreliable*, many clones exist
if (match(string: r, pattern: "statd version:*msgid:*"))
{
 register_service(port: port, proto: 'nagios-statd');
 security_note(port: port, data: 'nagios-statd seems to be running on this port');
 exit(0);
}

# 00: 22 49 4d 50 4c 45 4d 45 4e 54 41 54 49 4f 4e 22 "IMPLEMENTATION"
# 10: 20 22 43 79 72 75 73 20 74 69 6d 73 69 65 76 65 "Cyrus timsieve
# 20: 64 20 76 32 2e 32 2e 33 22 0d 0a 22 53 41 53 4c d v2.2.3".."SASL
# 30: 22 20 22 50 4c 41 49 4e 22 0d 0a 22 53 49 45 56 " "PLAIN".."SIEV
# 40: 45 22 20 22 66 69 6c 65 69 6e 74 6f 20 72 65 6a E" "fileinto rej
# 50: 65 63 74 20 65 6e 76 65 6c 6f 70 65 20 76 61 63 ect envelope vac
# 60: 61 74 69 6f 6e 20 69 6d 61 70 66 6c 61 67 73 20 ation imapflags
# 70: 6e 6f 74 69 66 79 20 73 75 62 61 64 64 72 65 73 notify subaddres
# 80: 73 20 72 65 6c 61 74 69 6f 6e 61 6c 20 72 65 67 s relational reg
# 90: 65 78 22 0d 0a 22 53 54 41 52 54 54 4c 53 22 0d ex".."STARTTLS".
# a0: 0a 4f 4b 0d 0a .OK..
if (match(string: r, pattern: '"IMPLEMENTATION""Cyrus timsieve d v*"*"SASL"*'))
{
 register_service(port: port, proto: 'sieve');
 security_note(port: port, data: 'Sieve mail filter daemon seems to be running on this port');
 exit(0);
}

# Running on 632/tcp
# 00: 54 68 65 20 73 6d 62 72 69 64 67 65 20 69 73 20 The smbridge is
# 10: 75 73 65 64 20 62 79 20 31 37 32 2e 32 30 2e 34 used by 172.20.4
# 20: 35 2e 31 38 38 0a 0d 54 68 65 20 63 6c 69 65 6e 5.188..The clien
# 30: 74 20 69 73 20 63 6c 6f 73 65 64 21 0a 0d t is closed!..

if (match(string: r, pattern: 'The smbridge is used by*'))
{
 register_service(port: port, proto: 'smbridge');
 security_note(port: port, data: 'IBM OSA SMBridge seems to be runnign on this port');
 exit(0);
}

# Running on 8649
# 00: 3c 3f 78 6d 6c 20 76 65 72 73 69 6f 6e 3d 22 31    <?xml version="1
# 10: 2e 30 22 20 65 6e 63 6f 64 69 6e 67 3d 22 49 53    .0" encoding="IS
# 20: 4f 2d 38 38 35 39 2d 31 22 20 73 74 61 6e 64 61    O-8859-1" standa
# 30: 6c 6f 6e 65 3d 22 79 65 73 22 3f 3e 0a 3c 21 44    lone="yes"?>.<!D
# 40: 4f 43 54 59 50 45 20 47 41 4e 47 4c 49 41 5f 58    OCTYPE GANGLIA_X
# 50: 4d 4c 20 5b 0a 20 20 20 3c 21 45 4c 45 4d 45 4e    ML [.   <!ELEMEN
# 60: 54 20 47 41 4e 47 4c 49 41 5f 58 4d 4c 20 28 47    T GANGLIA_XML (G
# 70: 52 49 44 29 2a 3e 0a 20 20 20 20 20 20 3c 21 41    RID)*>.      <!A
if (match(string: r, pattern: '<?xml version=*') && " GANGLIA_XML " >< r &&
 "ATTLIST HOST GMOND_STARTED" >< r)
{
 register_service(port: port, proto: 'gmond');
 security_note(port: port, data: 'Ganglia monitoring daemon seems to be runnign on this port');
 exit(0);
}

# Does not answer to GET, only to HELP
if (r == '\x06\x00\x00\x00\x00\x00\x1a\x00\x00\x00')
{
 register_service(port: port, proto: 'mldonkey-gui');
 security_note(port: port, data: 'MLDonkey is running on this port (GUI access)'); 
 exit(0); 
}

# If you do not want to "double check", uncomment the next two lines
# if (! r0) set_unknown_banner(port: port, banner: r);
# exit(0);

########################################################################
#                   **** WARNING ****                                  #
# Do not add anything below unless it should handled by find_service   #
# or find_service_3digits                                              #
# The exception is qotd -- look at the bottom of the file              #
########################################################################

function report_and_exit(port, data, hole)
{
  if (hole)
    security_hole(port: port, data: data);
  else
    security_note(port: port, data: data);

  if (report_verbosity > 1)
    security_warning(port: port, data:
"The service on this port should have been already identified
by other plugins.
find_service2 worked around this but your report might be incomplete.
You should increase the read timeout and rerun Nessus against this 
target");
  exit(0);
}

########################################################################
# All the following services should already have been identified by    #
# find_service.nes or find_service1.nasl; anyway, we double check in   #
# case they failed...                                                  #
########################################################################

if (r == 'HELP\r\n\r\n')
{
 register_service(port: port, proto: 'echo');
 report_and_exit(port:port, data: 'Echo "simple TCP/IP service" is running on this port');
}

# Spamd (port 783) - permissive Regex, just in case
if (r =~ '^SPAMD/[0-9.]+ [0-9]+ Bad header line:')
{
 register_service(port:port, proto:"spamd");
 report_and_exit(port:port, data:"A SpamAssassin daemon is running on this port");
}

# SOCKS5
if (ord(r[0]) == 5 && ord(r[1]) <= 8 && ord(r[2]) == 0 && ord(r[3]) <= 4)
{
  register_service(port: port, proto: "socks5");
  report_and_exit(port: port, data: "A SOCKS5 server seems to be running on this port");
}

# SOCKS4
if (ord(r[0]) == 0 && ord(r[1]) >= 90 && ord(r[1]) <= 93)
{
  register_service(port: port, proto: "socks4");
  report_and_exit(port: port, data: "A SOCKS4 server seems to be running on this port");
}

if (egrep(pattern:"^\+OK.*POP2.*", string:r, icase:1) )
{
  register_service(port:port, proto:"pop2");
  report_and_exit(port: port, data: "A pop2 server seems to be running on this port");
}

else if (egrep(pattern:"^\+OK.*POP.*", string:r, icase:1) )
{
  register_service(port:port, proto:"pop3");
  report_and_exit(port: port, data: "A pop3 server seems to be running on this port");
}
   

# FTP - note that SMTP & SNPP also return 220 & 214 codes
if (egrep(pattern:"^220 .*FTP", string:r, icase: 1) ||
    egrep(pattern:"^214-? .*FTP", string: r, icase: 1) ||
    egrep(pattern:"^220 .*CrownNet", string: r, icase: 1) ||
    (egrep(pattern:"^220 ", string:r) 
     && egrep(pattern: "^530 Please login with USER and PASS", string: r, icase: 1) )
   )
{
  banner = egrep(pattern:"^2[01][04]-? ", string: r);
  k = strcat("ftp/banner/", port);
  set_kb_item(name: k, value: banner);
  register_service(port: port, proto: "ftp");
  report_and_exit(port: port, data: "A FTP server seems to be running on this port");
}

# SMTP
if (egrep(pattern:"^220( |-).*(SMTP|mail)", string:r, icase: 1) ||
    egrep(pattern:"^214-? .*(HELO|MAIL|RCPT|DATA|VRFY|EXPN)", string: r) ||
    egrep(pattern:"^220-? .*OpenVMS.*ready", string: r) ||
    egrep(pattern:"^421-? .*SMTP", string: r))
{
  banner = egrep(pattern:"^2[01][04]-? ", string: r);
  k = strcat("smtp/banner/", port);
  set_kb_item(name: k, value: banner);
  register_service(port: port, proto: "smtp");
  report_and_exit(port: port, data: "A SMTP server seems to be running on this port");
}

# NNTP
if (egrep(pattern: "^200 .*(NNTP|NNRP)", string: r) ||
    egrep(pattern: "^100 .*commands", string: r, icase: 1))
{
  banner = egrep(pattern:"^200 ", string: r);
  if (banner)
  {
    k = strcat("nntp/banner/", port);
    set_kb_item(name: k, value: banner);
  }
  register_service(port: port, proto: "nntp");
  report_and_exit(port: port, data: "A NNTP server seems to be running on this port");
}

# SSH
banner = egrep(pattern: "^SSH-", string: r);
if (banner)
{
  register_service(port: port, proto: "ssh");
  report_and_exit(port: port, data: "A SSH server seems to be running on this port");
}

# Auth
if (egrep(string: r, pattern:"^0 *, *0 *: * ERROR *:") )
{
  register_service(port: port, proto: "auth");
  report_and_exit(port: port, data: "An Auth/ident server seems to be running on this port");
}

# Finger
if ((egrep(string: r, pattern: "HELP: no such user", icase: 1)) ||
    (egrep(string :r, pattern: ".*Line.*User.*Host", icase:1)) ||
    (egrep(string:r, pattern:".*Login.*Name.*TTY", icase:1)) ||
    '?Sorry, could not find "GET"' >< r ||
    'Login name: HELP' >< r  ||
    (('Time Since Boot:' >< r) && ("Name        pid" >< r) ))
{
  register_service(port: port, proto: "finger");
  report_and_exit(port: port, data: "A finger server seems to be running on this port");
}

# HTTP

if (("501 Method Not Implemented" >< r) || (ereg(string: r, pattern: "^HTTP/1\.[01]")) || "action requested by the browser" >< r)
{
  register_service(port: port, proto: "www");
  report_and_exit(port: port, data: "A web server seems to be running on this port");
}

# BitTorrent - no need to send anything to get the banner, in fact
if (r =~ "^BitTorrent protocol")
{
  register_service(port: port, proto: "BitTorrent");
  report_and_exit(port: port, data: "A BitTorrent server seems to be running on this port");
}

# Jabber (http://www.jabber.org) detection (usually on 5222/tcp).

if (r =~ "<stream:error>Invalid XML</stream:error>")
{
  register_service(port: port, proto: "jabber");
  report_and_exit(port: port, data: "A jabber server seems to be running on this port");
}

# Oracle Messenger (Jabber) detection (usually on 5222/tcp,5223/tcp for TLS).

if (r =~ "<stream:error>Connection is closing</stream:error></stream:stream>")
{
  register_service(port: port, proto: "jabber");
  report_and_exit(port: port, data: "A jabber server seems to be running on this port");
}

# Zebra vty
if ("Hello, this is zebra " >< r)
{
  register_service(port: port, proto: "zebra");
  set_kb_item(name: "zebra/banner/"+port, value: r);
  report_and_exit(port: port, data: "A zebra daemon is running on this port");
}

# IMAP4

if (egrep(pattern:"^\* *OK .* IMAP", string:r) )
{
  register_service(port: port, proto: "imap");
  set_kb_item(name: "imap/banner/"+port, value: r);
  report_and_exit(port: port, data: "An IMAP server is running on this port");
}

if ("cvs [pserver]" >< r )
{
  register_service(port: port, proto: "cvspserver");
  report_and_exit(port: port, data: "A CVS pserver is running on this port");
}

if ( '"IMPLEMENTATION" "Cyrus timesieved"' >< r )
{
  register_service(port: port, proto: "cyrus-timsieved");
  report_and_exit(port: port, data: "Cyrus timesived is running on this port");
}


if ("@ABCDEFGHIJKLMNOPQRSTUV" >< r )
{
  register_service(port:port, proto: "chargen");
  report_and_exit(port: port, data: "A chargen server is running on this port");
}

# This is an IRC bouncer!
if ( egrep(pattern:":Welcome!.*NOTICE.*psyBNC", icase:TRUE, string:r ) ) 
{
  register_service(port:port, proto: "psyBNC");
  report_and_exit(port: port, hole: 1, data: "psyBNC seems to be running on this port");
}

if ( "CCProxy Telnet Service Ready" >< r )
{
  register_service(port:port, proto: "ccproxy-telnet");
  security_note(port: port, data: "CCProxy (telnet) seems to be running on this port");
  exit(0);
}

if ( "CCProxy FTP Service" >< r )
{
  register_service(port:port, proto: "ccproxy-ftp");
  security_note(port: port, data: "CCProxy (ftp) seems to be running on this port");
  exit(0);
}
if ( "CCProxy " >< r  && "SMTP Service Ready" >< r )
{
  register_service(port:port, proto: "ccproxy-smtp");
  security_note(port: port, data: "CCProxy (smtp) seems to be running on this port");
  exit(0);
}

if ( "CMailServer " >< r  && "SMTP Service Ready" >< r )
{
  register_service(port:port, proto: "cmailserver-smtp");
  security_note(port: port, data: "CMailServer (smtp) seems to be running on this port");
  exit(0);
}

# 0000000 30 11 00 00 00 00 00 00 d7 a3 70 3d 0a d7 0d 40
#          0 021  \0  \0  \0  \0  \0  \0   ×   £   p   =  \n   ×  \r   @
# 0000020 00 00 00 00 00 00 00 00 01 00 00 00 01 00 00 00
#         \0  \0  \0  \0  \0  \0  \0  \0 001  \0  \0  \0 001  \0  \0  \0
# 0000040 00 00 00 00 02 00 00 00
#         \0  \0  \0  \0 002  \0  \0  \0
# 0000050

if (r =~ '^\x30\x11\x00\x00\x00\x00\x00\x00\xd7\xa3')
{
  register_service(port: port, proto: 'dameware');
  security_note(port: port, data: "Dameware seems to be running on this port");
  exit(0);
}

if ( "Open DC Hub, version" >< r  && "administrators port" >< r )
{
  register_service(port:port, proto: "opendchub");
  security_note(port: port, data: "Open DC Hub Administrative interface (peer-to-peer) seems to be running on this port");
  exit(0);
}

if ( ereg(pattern:"^RFB [0-9]", string:r) )
{
  register_service(port:port, proto: "vnc");
  security_note(port: port, data: "A VNC server seems to be running on this port");
  exit(0);
}

if ( egrep(pattern:"^BZFS00", string:r) )
{
  register_service(port:port, proto:"bzFlag");
  security_note(port: port, data: "A bzFlag server seems to be running on this port");
  exit(0);
  
}

# MS DTC

if (strlen(r) == 3 && (r[2] == '\x10'||	# same test as find_service
                       r[2] == '\x0b') ||
    r == '\x78\x01\x07' || r == '\x10\x73\x0A' || r == '\x78\x01\x07' ||
    r == '\x08\x40\x0c' )
{
  register_service(port: port, proto: "msdtc");
  security_note(port: port, data: "A MSDTC server seems to be running on this port");
  exit(0);
}

if (r == 'GIOP\x01')
{
 register_service(port:port, proto:"giop");
 security_note(port: port, data: "A GIOP-enabled service is running on this port");
 exit(0);
}

#
# Keep qotd at the end of the list, as it generates false detection
#
if (egrep(pattern: "^[A-Za-z. -]+\([0-9-]+\)", string: r))
{
  register_service(port:port, proto: "qotd");
  security_note(port: port, data: "qotd seems to be running on this port");
  exit(0);
}

########################################################################
#             Unidentified service                                     #
########################################################################

if (! r0) set_unknown_banner(port: port, banner: r);
