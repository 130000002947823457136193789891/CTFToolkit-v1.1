#
# (C) Tenable Network Security
#
# Ref: 
# Date: 22 Jul 2003 15:05:29 -0000
# From: phil dunn <z3hp@yahoo.com>
# To: bugtraq@securityfocus.com
# Subject: sorry, wrong file


if(description)
{
 script_id(11799);
 script_bugtraq_id(8241);
 script_version ("$Revision: 1.7 $");


 name["english"] = "PHP Ashnews code injection";
 script_name(english:name["english"]);
 
 desc["english"] = "
It is possible to make the remote host include php files hosted
on a third party server using PHP Ashnews.

An attacker may use this flaw to inject arbitrary code in the remote
host and gain a shell with the privileges of the web server.

Solution : Upgrade to the latest version of this software
Risk factor : High";




 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of ashnews.php";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("phpgroupware_detect.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

kb = get_kb_item("www/" + port + "/phpGroupWare");
if ( ! kb ) exit(0);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);


matches = eregmatch(pattern:"(.*) under (.*)", string:kb);

loc = matches[2];
req = http_get(item:string(loc, "/ashnews.php?pathtoashnews=http://xxxxxxxx/"), port:port);
r = http_keepalive_send_recv(port:port, data:req);
if( r == NULL ) exit(0);
if(egrep(pattern:".*http://xxxxxxxx/ashprojects/newsconfig\.php", string:r))
 	security_hole(port);
