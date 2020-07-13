#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10358);
 script_bugtraq_id(189);
 script_cve_id("CAN-1999-1538");
 script_version ("$Revision: 1.15 $");

 name["english"] = "/iisadmin is world readable";
 name["francais"] = "/iisadmin est en lecture libre";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
The use of /iisadmin is not limited to the loopback address.
Anyone can use it to reconfigure your web server.

Solution : Restrict access to /iisadmin through the IIS ISM
Risk factor : High";


 desc["francais"] = "
L'usage de /iisadmin n'est pas limité à l'interface
loopback.

N'importe qui peut donc s'en servir pour reconfigurer
votre serveur web

Solution : restreignez son accès via l'ISM d'IIS
Facteur de risque : Elevé";


 script_description(english:desc["english"], francais:desc["francais"]);
 
 summary["english"] = "Checks for the presence of /iisadmin";
 summary["francais"] = "Vérifie la présence de /iisadmin";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl", "www_fingerprinting_hmap.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");
port = get_http_port(default:80);

banner = get_http_banner(port:port);
if ( ! banner || "Microsoft-IIS/" >!< banner ) exit(0);
if ( ! get_port_state(port) ) exit(0);

res = http_keepalive_send_recv(port:port, data:http_get(port:port, item:"/iisadmin/"));
if ( ereg(pattern:"HTTP/[01]\.[01] 200 ", string:res) &&
     "<TITLE>IIS Internet Services Manager (HTMLA)</TITLE>" >< res ) security_hole(port);
