#
# (C) Noam Rathaus GPLv2
#
# From: Janek Vind <come2waraxe@yahoo.com>
# Subject: Critical Sql Injection in Sgallery module for PhpNuke
# Date: 2005-01-13 05:08

if(description)
{
 script_id(16164);
 script_version("$Revision: 1.3 $");
 script_bugtraq_id(12249);
 
 name["english"] = "SGallery idimage SQL Injection";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running SGallery, a module for PHP-Nuke.

A critical SQL injection in the remote version of this module has been 
found, this vulnerability allows a remote attacker via the 'idimage' 
variable to inject arbitrary SQL statements in the remote SQL database.

Solution : Upgrade to the latest version of this software.
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of an SQL injection in idimage parameter";
 
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

function check(loc)
{
 req = http_get(item:string(loc, "/imageview.php?idimage='"), port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly: 1);
 if ( r == NULL ) exit(0);
 if ( "You have an error in your SQL syntax near '\'' at line 1" >< r )
 { 
  security_hole(port: port);
  exit(0);
 }
}

foreach dir ( cgi_dirs() )
{
 check(loc:dir);
}
