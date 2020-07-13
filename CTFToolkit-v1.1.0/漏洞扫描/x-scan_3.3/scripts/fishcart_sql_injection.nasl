#
# (C) Noam Rathaus GPLv2
#

# Multiple SQL injections and XSS in FishCart 3.1
# "Diabolic Crab" <dcrab@hackerscenter.com>
# 2005-05-03 23:07

if(description)
{
 script_id(18191);
 script_cve_id("CAN-2005-1486", "CAN-2005-1487");
 script_bugtraq_id(13499);
 script_version("$Revision: 1.3 $");

 name["english"] = "FishCart SQL injections";

 script_name(english:name["english"]);
 
 desc["english"] = "
FishCart, in use since January 1998, is a proven Open Source 
e-commerce system for products, services, online payment and
online donation management. Written in PHP4, FishCart has
been tested on Windows NT, Linux, and various Unix platforms.
FishCart presently supports the MySQL, PostgreSQL, Solid, Oracle and MSSQL.

FishCart contains multiple SQL injection vulnerabilities in the program
that can be exploited to modify/delete/insert entries into the database.

In addition, the program suffers from cross site scripting vulnerabilities.

Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of an SQL injection in upstnt.asp";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
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

debug = 0;

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

function check(loc)
{
 req = http_get(item:string(loc, "/upstnt.php?zid=1&lid=1&cartid='"), port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly: 1);
 if( r == NULL )exit(0);
 if("Invalid SQL: select sku,qty from mwestoline where orderid='''" >< r)
 {
  security_hole(port);
  exit(0);
 }
}

foreach dir ( cgi_dirs() )
{
 check(loc:dir);
}
