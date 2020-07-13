#
# (C) Tenable Network Security
#
# See the Nessus Scripts License for details
#


if(description)
{
 script_id(14324);
 script_bugtraq_id(10993, 10994, 10995);
 script_version ("$Revision: 1.3 $");

 name["english"] = "Mantis Multiple Flaws (2)";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running the Mantis bug tracker.

The remote version of this software contains multiple flaws which may
allow an attacker to use it to perform a mass emailing, to inject
HTML tags in the remote pages or to execute arbitrary commands on the
remote host if the PHP configuration variable 'register_globals' 
is set.

Solution : Upgrade to Mantis 0.18.3 or 0.19.0a2 or newer 
Risk factor : High"; 




 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the version of Mantis";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security",
		francais:"Ce script est Copyright (C) 2004 Tenable Network Security");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "no404.nasl", "mantis_detect.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);

vers = get_kb_item(string("www/", port, "/mantis/version"));
if(!vers)exit(0);
if(ereg(pattern:"0\.([0-9]\.|1[0-7]\.|18\.[0-2][^0-9]|19\.0 *a[01])", string:vers))
	security_hole(port);
	
