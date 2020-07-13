#
# This cgi abuse script was written by Jonathan Provencher
# Ce script de scanning de cgi a ete ecrit par Jonathan Provencher
# <druid@balistik.net>
#


if(description)
{
 script_id(10321);
 script_bugtraq_id(649, 12453);
 script_version ("$Revision: 1.14 $");
 script_cve_id("CVE-1999-0953");
 
 name["english"] = "wwwboard passwd.txt";
 name["francais"] = "wwwboard passwd.txt";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The remote host is running wwwboard, a bulletin board system written
by Matt Wright.

This board system comes with a password file (passwd.txt) installed
next to the file 'wwwboard.html'.

An attacker may obtain the content of this file and decode the password
to modify the remote www board.

Solution : Configure the wwwadmin.pl script to change the location of passwd.txt
Risk factor : High";





 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of /wwwboard/passwd.txt";
 summary["francais"] = "Vérifie la présence de /wwwboard/passwd.txt";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 1999 Jonathan Provencher",
		francais:"Ce script est Copyright (C) 1999 Jonathan Provencher"
	);	

 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 	

 script_dependencie("find_service.nes", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");
port = get_http_port(default:80);

foreach dir(cgi_dirs())
{
 res = http_keepalive_send_recv(port:port, data:http_get(port:port, item:dir + "/wwwboard.html"));
 if (res == NULL )exit(0);
 if ( "wwwboard.pl" >< res )
 {
 res = http_keepalive_send_recv(port:port, data:http_get(port:port, item:dir + "/passwd.txt"), bodyonly:TRUE);
 if ( strlen(res) && egrep(pattern:"^[A-Za-z0-9]*:[a-zA-Z0-9-_.]$", string:res))
	{
	 security_hole(port);
	 exit(0);
	}
 }
}

