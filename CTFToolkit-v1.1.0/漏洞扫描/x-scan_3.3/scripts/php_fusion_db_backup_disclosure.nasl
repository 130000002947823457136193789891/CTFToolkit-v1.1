#
# (C) Tenable Network Security
#
if(description)
{
 script_id(14356);
 script_cve_id("CAN-2004-1724");
 script_bugtraq_id(10974);
 script_version("$Revision: 1.3 $");
 
 name["english"] = "PHP-Fusion Database Backup Disclosure";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using PHP-Fusion, a content management system, 
written in PHP which uses MySQL.

A vulnerability exists in the remote version of this product which may allow 
an attacker to obtain a dump of the remote database. PHP-Fusion has the
ability to create database backups and store them on the web server, 
in the directory fusion_admin/db_backups/. 

Since there is no access control on that directory, an attacker may
guess the name of a backuped database and download it.

Solution : Upgrade to the latest version of this software
Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the version of the remote PHP-Fusion";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("php_fusion_detect.nasl");
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

kb = get_kb_item("www/" + port + "/php-fusion");
if ( ! kb ) exit(0);

items = eregmatch(string:kb, pattern:"(.*) under (.*)");
loc   = items[2];

req = http_get(item:string(loc, "/index.php"), port:port);
r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
if( r == NULL )exit(0);
if ( "PHP-Fusion" >< r && ereg(pattern:"^([0-3]\.|4\.00)", string:items[1])  )
{
  req = http_get(item:string(loc, "/fusion_admin/db_backups/"), port:port);
  r = http_keepalive_send_recv(port:port, data:req);
  if ( r == NULL ) exit(0);
  if ( egrep(pattern:"^HTTP/.* 200 .*", string:r) )
	{ 
  	security_warning(port);
	}
  exit(0);
}
