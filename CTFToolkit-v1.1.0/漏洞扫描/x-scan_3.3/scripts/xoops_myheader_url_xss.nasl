#
# This script was written by Noam Rathaus
#
# GPLv2
#
# From: Chintan Trivedi [chesschintan@hotmail.com]
# Subject: XSS vulnerability in XOOPS 2.0.5.1
# Date: Sunday 21/12/2003 16:45
#
#

if(description)
{
  script_id(11962);
  script_bugtraq_id(9269);
  script_version("$Revision: 1.5 $");
  name["english"] = "Xoops myheader.php URL Cross Site Scripting Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
The remote host is hosting the XOOPS CGI suite.

The weblinks module of XOOPS contains a file named 'myheader.php'
in /modules/mylinks/ directory. The code of the module insufficently
filters out user provided data. The URL parameter used by 'myheader.php'
can be used to insert malicious HTML and/or JavaScript in to the web
page.
 
Solution : Upgrade to the latest version of XOOPS
Risk factor : Medium";

  script_description(english:desc["english"]);
 
  summary["english"] = "Detect Xoops myheader.php URL XSS";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2003 Noam Rathaus");

  family["english"] = "General";
  script_family(english:family["english"]);
  script_dependencie("find_service.nes", "http_version.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);

if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port))exit(0);

quote = raw_string(0x22);

function check_dir(path)
{
 req = http_get(item:string(path, "/modules/mylinks/myheader.php?url=javascript:foo"), port:port);
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if ( res == NULL ) exit(0);
 find = string("href=", quote, "javascript:foo", quote);


 if ( find >< res )
 {
  security_warning(port);
  exit(0);
 }
}

foreach dir (cgi_dirs())
{
 check_dir(path:dir);
}

