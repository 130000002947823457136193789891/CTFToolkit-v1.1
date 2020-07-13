#
# This script was written by Noam Rathaus
#
# GPLv2
#
# From: Zero_X www.lobnan.de Team [zero-x@linuxmail.org]
# Subject: Remote Code Execution in Knowledge Builder
# Date: Wednesday 24/12/2003 15:45
#
#

if(description)
{
  script_id(11959);
  script_version("$Revision: 1.4 $");
  name["english"] = "Remote Code Execution in Knowledge Builder";
  script_name(english:name["english"]);
 
  desc["english"] = "
KnowledgeBuilder is a feature-packed knowledge base solution CGI suite. 

A vulnerability in this product may allow a remote attacker to execute 
arbitrary commands on this host.

Solution : Upgrade to the latest version or disable this CGI altogether
Risk factor : High";

  script_description(english:desc["english"]);
 
  summary["english"] = "Detect Knowledge Builder Code Execution";
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

debug = 0;

port = get_http_port(default:80);

if (! get_port_state(port) ) exit(0);
if (! can_host_php(port:port) ) exit(0);

function check_dir(path)
{
 req = http_get(item:string(path, "/index.php?page=http://xxxxxxxxxxxxx/nessus"), port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);
 find = string("operation error");
 find_alt = string("getaddrinfo failed");

 if (find >< res || find_alt >< res )
 {
  req = http_get(item:string(path, "/index.php?page=index.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req);
  if ( res == NULL ) exit(0);
  if ( find >< res || find_alt >< res ) exit(0);
  security_warning(port);
  exit(0);
 }
}

foreach dir (make_list("/kb", cgi_dirs())) check_dir(path:dir);

