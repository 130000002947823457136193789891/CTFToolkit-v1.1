#
# This script was written by Noam Rathaus
#
# GPLv2
#
# From: Zero_X www.lobnan.de Team [zero-x@linuxmail.org]
# Subject: Remote Code Execution in ezContents
# Date: Saturday 10/01/2004 19:14
#
#

if(description)
{
  script_id(12021);
  script_cve_id("CVE-2004-0070");
  script_bugtraq_id(9396);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"6878");
  }
  script_version("$Revision: 1.4 $");
 
  name["english"] = "Remote Code Execution in ezContents";
  script_name(english:name["english"]);
 
  desc["english"] = "
ezContents is an Open-Source website content management system based
on PHP and MySQL. Features include maintaining menus and sub-menus,
adding authors that write contents, permissions, workflow, and
layout possibilities for the entire look of the site by simple use of settings.

The product has been found to contain a vulnerability that would allow
a remote attacker to cause the PHP script to include an external PHP
file and execute its content. This would allow an attacker to cause
the server to execute arbitrary code.

Risk factor : High";

  script_description(english:desc["english"]);
 
  summary["english"] = "Detect ezContents Code Execution";
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

port = get_http_port(default:80);

if( ! get_port_state(port) ) exit(0);
if( ! can_host_php(port:port) ) exit(0);

function check_dir(path)
{
 req = http_get(item:string(path, "/module.php?link=http://xxxx./index.php"), port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);
 if ( egrep(pattern:"main.*'http://xxxx\./index\.php'.*modules\.php",
	    string:res))
 {
  security_hole(port);
  exit(0);
 }
}

foreach dir (cgi_dirs())
{
 check_dir(path:dir);
}
