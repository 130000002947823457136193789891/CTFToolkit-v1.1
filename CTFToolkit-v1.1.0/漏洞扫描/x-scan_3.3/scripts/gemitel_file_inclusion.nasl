#
# This script was written by Noam Rathaus
#
# GPLv2
#
# From: jaguar <webmaster@wulab.com>
# Subject: Include vulnerability in GEMITEL v 3.50
# Date: 2004-04-15 16:26
#
#

if(description)
{
  script_id(12214);
  script_cve_id("CAN-2004-1934");
  script_bugtraq_id(10156);
  script_version("$Revision: 1.3 $");
  name["english"] = "File Inclusion Vulnerability in Gemitel";
  script_name(english:name["english"]);
 
  desc["english"] = "
A vulnerability in Gimtel allows a remote attacker to execute
arbitrary commands on this host.

Solution : Upgrade to the latest version or disable this CGI altogether
Risk factor : High";

  script_description(english:desc["english"]);
 
  summary["english"] = "Detect Gimtel File Inclusion Vulnerability";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2004 Noam Rathaus");

  family["english"] = "General";
  script_family(english:family["english"]);
  script_dependencie("http_version.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if (! get_port_state(port) ) exit(0);
if (! can_host_php(port:port) ) exit(0);

function check_dir(path)
{
 req = http_get(item:string(path, "/html/affich.php?base=http://xxx.xxxxxx./"), port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);
 if (egrep(pattern:"http://xxx\.xxxxxx\./sp-turn\.php", string:res) )
 {
  security_warning(port);
  exit(0);
 }
}

foreach dir (make_list("/gimtel", cgi_dirs())) check_dir(path:dir);

