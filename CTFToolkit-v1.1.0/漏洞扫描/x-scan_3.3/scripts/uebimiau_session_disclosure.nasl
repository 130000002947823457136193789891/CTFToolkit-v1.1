#
# (C) Noam Rathaus GPLv2
#
# ITTS ADVISORE 01/05 - Uebimiau <= 2.7.2 Multiples Vulnerabilities
# Martin Fallon <mar_fallon@yahoo.com.br>
# 2005-01-27 14:09

if(description)
{
 script_id(16279);
 script_version("$Revision 1.1$");
 
 name["english"] = "Uebimiau Session Directory Disclosure";

 script_name(english:name["english"]);
 
 desc["english"] = "
UebiMiau is a simple and cross-plataform POP3/IMAP mail
reader written in PHP.

Uebimiau in default installation create one temporary folder 
to store 'sessions' and other files. This folder is defined 
in 'inc/config.php' as './database/'.

If the web administrator don't change this folder, an attacker
can exploit this using the follow request:
http://server-target/database/_sessions/

Solutions:
1) Insert index.php in each directory of the Uebimiau

2) Set variable $temporary_directory to a directory 
not public and with restricted access, set permission
as read only to 'web server user' for each files in
$temporary_directory.

3) Set open_basedir in httpd.conf to yours clients follow  
the model below:

<Directory /server-target/public_html>
 php_admin_value open_basedir
 /server-target/public_html
</Directory>

Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of sessions directory of UebiMiau";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Noam Rathaus");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "httpver.nasl", "http_version.nasl");
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
 req = http_get(item:string(loc, "/database/_sessions/"), port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly: 1);
 if( r == NULL )exit(0);

 if (( "Parent Directory" >< r) && ("/database/_sessions" >< r))
 {
  security_warning(port);
  exit(0);
 }
}

foreach dir (make_list("", "/uebimiau-2.7.2", "/mailpop", "/webmail", cgi_dirs()))
{
 check(loc:dir);
}

