#
# This script was written by Matt Moore <matt.moore@westpoint.ltd.uk>
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11046);
 script_bugtraq_id(4575);
 script_version("$Revision: 1.12 $");
 name["english"] = "Apache Tomcat TroubleShooter Servlet Installed";
 name["francais"] = "Apache Tomcat TroubleShooter Servlet Installed";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "The default installation of Tomcat includes various sample jsp pages and servlets. One of these, the 'TroubleShooter' servlet, discloses various information about the system on which Tomcat is installed. This servlet can also be used to perform cross-site scripting attacks.

Solution: 

Example files should not be left on production servers.

References: 

http://www.osvdb.org/displayvuln.php?osvdb_id=849

Risk factor : Low";

 script_description(english:desc["english"]);
 
 summary["english"] = "Tests whether the Apache Tomcat TroubleShooter Servlet is installed";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002 Matt Moore",
		francais:"Ce script est Copyright (C) 2002 Matt Moore");
 family["english"] = "CGI abuses : XSS";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes","http_version.nasl");
 script_require_ports("Services/www", 80, 8080);
 script_require_keys("www/apache");
 exit(0);
}

# Check starts here

include("http_func.inc");

port = get_http_port(default:80);
if(! port || ! get_port_state(port)) exit(0);

sig = get_kb_item("www/hmap/"  + port  + "/description");
if ( sig && "Apache" >!< sig && "Tomcat" >!<  sig ) exit(0);

req = http_get(item:"/examples/servlet/TroubleShooter", port:port);
soc = http_open_socket(port);
if(soc)
 {
 send(socket:soc, data:req);
 r = http_recv(socket:soc);
 http_close_socket(soc);
 confirmed = string("TroubleShooter Servlet Output"); 
 confirmed_too = string("hiddenValue");
 if ((confirmed >< r) && (confirmed_too >< r)) 	
 	security_warning(port);

 }
