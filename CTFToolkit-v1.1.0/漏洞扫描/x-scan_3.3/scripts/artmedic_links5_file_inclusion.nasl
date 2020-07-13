#
# (C) Noam Rathaus
#
# From: Adam n30n Simuntis <n30n@satfilm.net.pl>
# Subject: artmedic_links5 PHP Script (include path) vuln
# Date: 25.6.2004 19:51

if(description)
{
 script_id(12289);
 script_version("$Revision: 1.3 $");
 
 name["english"] = "artmedic_links5 File Inclusion Vulnerability";
 script_name(english:name["english"]);
 
 desc["english"] = "
Artmedic Links a links generating PHP script,
has been found to contain an external file inclusion vulnerability. 

Impact:
The file inclusion vulnerability allows a remote attacker to include
external PHP files as if they were the server's own, this causing the
product to execute arbitrary code

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for artmedic_links5's PHP inclusion vulnerability";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
  
 script_copyright(english:"This script is Copyright (C) 2004 Noam Rathaus");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

debug = 0;
port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

foreach dir (cgi_dirs())
{
 req = string(dir,"/artmedic_links5/index.php?id=index.php");
 req = http_get(item:req, port:port);
 buf = http_keepalive_send_recv(port:port, data:req);
 if( buf == NULL ) exit(0);

 if ('require("linksscript/include.php");' >< buf ) 
	{
	security_hole(port);
	exit(0);
	}
}

