#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10304);
 script_bugtraq_id(969);
 script_version ("$Revision: 1.14 $");
 script_cve_id("CVE-2000-0127");
 
 name["english"] = "WebSpeed remote configuration";
 name["francais"] = "configuration a distance de WebSpeed";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
It may be possible for an attacker to reconfigure the 
remote web server by requesting :

	GET /scripts/wsisa.dll/WService=anything?WSMadmin
	
	
Solution : Edit the ubroker.properties file and change
	AllowMsngrCmds = 1
to :
	AllowMsngrCmds = 0
	
	
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks if webspeed can be administered";
 summary["francais"] = "Détermine s'il est possible d'administrer webspeed";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2000 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl");
  script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");
port = get_http_port(default:80);

cgi = "/scripts/wsisa.dll/WService=anything?WSMadmin";
res = is_cgi_installed_ka(item:cgi, port:port);
if(res)security_hole(port);
 


