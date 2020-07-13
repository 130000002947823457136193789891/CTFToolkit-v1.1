#
# This script was written by Noam Rathaus
#
# GPLv2
#
# From: Andrew Smith [parenthesis@elitehaven.net]
# Subject: Multiple Vulns in Psychoblogger beta1
# Date: Wednesday 24/12/2003 01:52
#
#

if(description)
{
  script_id(11961);
  script_version("$Revision: 1.4 $");
  name["english"] = "Psychoblogger SQL Injection";
  script_name(english:name["english"]);
 
  desc["english"] = "
Psychoblogger is a CMS package aimed at providing weblogs (or 'blogs') with
an easy to set up system for editing and authoring the content. One of its
scripts contains an SQL injection vulnerability.

An attacker may use this flaw to gain the control of the remote database and
create arbitrary accounts.


Solution : Upgrade to the latest version of this CGI suite.
Risk factor : High";

  script_description(english:desc["english"]);
 
  summary["english"] = "Detect Psychoblogger SQL Injection";
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

if ( ! get_port_state(port) ) exit(0);
if ( ! can_host_php(port:port) ) exit(0);


function check_dir(path)
{
 req = http_get(item:string(path, "/shouts.php?shoutlimit='"), port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);

 find = "You have an error in your SQL syntax near '";

 if ( find >< res ) 
 {
  security_hole(port);
  exit(0);
 }
}

foreach dir (cgi_dirs())
{
 check_dir(path:dir);
}
