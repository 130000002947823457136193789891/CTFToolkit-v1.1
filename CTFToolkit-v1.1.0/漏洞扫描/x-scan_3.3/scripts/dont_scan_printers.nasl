# This script was written by Michel Arboi <arboi@alussinan.org>
#
# Released under GPLv2
#

if(description)
{
 script_id(11933);
 script_version ("$Revision: 1.17 $");
 name["english"] = "Do not scan printers";
 script_name(english:name["english"]);

 desc["english"] = "
The host seems to be a printer.

Scanning it is usually destructive and will waste paper, so its
scan has been interrupted.

** If you want to scan your printers, disable this script 
** (ID=11933, family 'Settings')

Risk factor : None";

 script_description(english:desc["english"]);

 summary["english"] = "Exclude AppSocket & socketAPI printers from scan";
 script_summary(english:summary["english"]);

 script_category(ACT_SETTINGS);

# script_add_preference(name:"Exclude printers from scan", type:"checkbox", value:"no");

 script_copyright(english:"This script is Copyright (C) 2003 by Michel Arboi");
 family["english"] = "Settings";	
# Or maybe a "scan option" family?
 script_family(english:family["english"]);
 exit(0);
}


include("ftp_func.inc");
include("telnet_func.inc");
include("http_func.inc");
include("global_settings.inc");

# pref= script_get_preference("Exclude printers from scan");
# if (!pref || pref == "no") exit(0);

if (! safe_checks()) exit(0);

# First try UDP AppSocket

port = 9101;
if (get_udp_port_state(port))
{
  soc = open_sock_udp(port);

  send(socket: soc, data: '\r\n');
  r = recv(socket: soc, length: 512);
  if (r)
  {
    set_kb_item(name: "Host/dead", value: TRUE);
    if (debug_level) display(get_host_ip(), " answers to UDP AppSocket\n");
    security_note(port: 0);
    exit(0);
  }
}

port = 21;
if(get_port_state(port))
{
 banner = get_ftp_banner(port:port);
 if("JD FTP Server Ready" >< banner)
 {
    set_kb_item(name: "Host/dead", value: TRUE);
    if (debug_level) display(get_host_ip(), " runs JD FTP server\n");
    security_note(port: 0);
    exit(0);
 }
 else if ("220 Dell Laser Printer " >< banner)
 {
    set_kb_item(name: "Host/dead", value: TRUE);
    if (debug_level) display(get_host_ip(), " runs Dell FTP server\n");
    security_note(port: 0);
    exit(0);
 }
}

port = 23;
if(get_port_state(port))
{
 banner = get_telnet_banner(port:port);
 if("HP JetDirect" >< banner)
 {
    set_kb_item(name: "Host/dead", value: TRUE);
    if (debug_level) display(get_host_ip(), " runs HP JetDirect Telnet server\n");
    security_note(port: 0);
    exit(0);
 }
}

# Xerox DocuPrint
port = 2002;
if ( get_port_state(port) )
{
 soc = open_sock_tcp(port);
 if ( soc )
 {
  banner = recv(socket:soc, length:23);
  close(soc);
  if ( banner && 'Please enter a password' >< banner ) {
    	set_kb_item(name: "Host/dead", value: TRUE);
    	security_note(port: 0);
	exit(0);
	}
 }
}



# Patch by Laurent Facq
ports = make_list(80, 280, 631);
foreach port (ports)
{
 if(get_port_state(port))
 {
  banner = http_send_recv(port:port, data:string("GET / HTTP/1.0\r\n\r\n"));
  if("Dell Laser Printer " >< banner )
  {
     set_kb_item(name: "Host/dead", value: TRUE);
    if (debug_level) display(get_host_ip(), " runs Dell web server\n");
     security_note(port: 0);
     exit(0);
  }
  else if("<title>Hewlett Packard</title>" >< banner)
  {
     set_kb_item(name: "Host/dead", value: TRUE);
    if (debug_level) display(get_host_ip(), " runs HP web server\n");
     security_note(port: 0);
     exit(0);
  }
  else if ( banner && "Server: Xerox_MicroServer/Xerox" >< banner )
  {
     set_kb_item(name: "Host/dead", value: TRUE);
    if (debug_level) display(get_host_ip(), " runs a Xerox web server\n");
    security_note(port: 0);
    exit(0);
  }
 }
}


# open ports?
ports = get_kb_list("Ports/tcp/*");
# Host is dead, or all ports closed, or unscanned => cannot decide
if (isnull(ports)) exit(0);
# Ever seen a printer with more than 8 open ports?
# if (max_index(ports) > 8) exit(0);

# Test if open ports are seen on a printer
# http://www.lprng.com/LPRng-HOWTO-Multipart/x4981.htm
appsocket = 0;


foreach p (keys(ports))
{
  p = int(p - "Ports/tcp/");
  if (	   p == 35		# AppSocket for QMS
	|| p == 2000		# Xerox
	|| p == 2501		# AppSocket for Xerox
	|| (p >= 3001 && p <= 3005)	# Lantronix - several ports
	|| (p >= 9100 && p <= 9300)	# AppSocket - several ports
#        || p == 10000 		# Lexmark
	|| p == 10001)		# Xerox - programmable :-(
    appsocket = 1;
# Look for common non-printer ports
	 else if (
          p != 21              # FTP
       && p != 23              # telnet
       && p != 79
       && p != 80              # www
       && p != 139 && p!= 445  # SMB
       && p != 280             # http-mgmt
       && p != 443
       && p != 515             # lpd
       && p != 631 	       # IPP
       && p != 8000 
       && (p < 5120 || p > 5129))  # Ports 512x are used on HP printers    
	exit(0);

}


# OK, this might well be an AppSocket printer
if (appsocket)
{
  security_note(0);
  if (debug_level) display(get_host_ip(), " looks like an AppSocket printer\n");
  set_kb_item(name: "Host/dead", value: TRUE);
}
