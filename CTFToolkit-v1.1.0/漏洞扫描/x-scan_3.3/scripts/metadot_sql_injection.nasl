#
# This script was written by Noam Rathaus
#
# GPLv2
#
# From: JeiAr [security@gulftech.org]
# Subject: Multiple MetaDot Vulnerabilities [ All Versions ]
# Date: Friday 16/01/2004 03:11
#
#

if(description)
{
  script_id(12024);
  script_bugtraq_id(9439);
  script_version("$Revision: 1.6 $");
  name["english"] = "Multiple MetaDot Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
The remote host is running Metadot, a popular open source portal software. 


Multiple vulnerabilities have been found in this product, which may allow a 
malicious user to inject arbitrary SQL commands, reveal valuable information 
about the server and perform Cross Site Scripting attacks.

Solution : Upgrade to the latest version of Metadot
Risk factor : High";

  script_description(english:desc["english"]);
 
  summary["english"] = "Detect MetaDot SQL Injection";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2004 Noam Rathaus");

  family["english"] = "CGI abuses : XSS";
  script_family(english:family["english"]);
  script_dependencie("find_service.nes", "http_version.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if (! get_port_state(port) ) exit(0);

function check_dir(path)
{
 req = http_get(item:string(path, "/metadot/index.pl?isa=Session&op=auto_login&new_user=&key='[foo]"), port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);
 find = "DBAccess::sqlSelect('DBAccess', 'uid', 'session', 'sessionid=\'\'[foo]\'')";
 if ( find >< res )
 {
  security_hole(port);
  exit(0);
 }
}


foreach dir (cgi_dirs()) check_dir(path:dir);
