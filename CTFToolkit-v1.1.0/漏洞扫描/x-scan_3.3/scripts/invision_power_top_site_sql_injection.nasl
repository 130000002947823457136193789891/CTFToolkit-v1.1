#
# This script was written by Noam Rathaus
#
# GPLv2
#
# From: JeiAr [security@gulftech.org]
# Subject: Invision Power Top Site List SQL Inection
# Date: Monday 15/12/2003 23:38
#
#
# Changes by rd:
# - Use the HTTP api instead of hardcoding HTTP requests
# - changed the description

if(description)
{
  script_id(11956);
  script_bugtraq_id(9229);
  script_version ("$Revision: 1.5 $");
 
  name["english"] = "Invision Power Top Site List SQL Injection";
  script_name(english:name["english"]);
 
  desc["english"] = "
The remote host is running 'Invision Power Top Site List', a site ranking
script written in PHP.

There is a SQL injection vulnerability in this CGI suite, due to a lack
of user-input sanitizing, which may allow an attacker to execute arbitrary
SQL commands on this host, and therefore gain the control of the database
of this site.

Solution : Upgrade to the latest version of this CGI suite
Risk factor : High";

  script_description(english:desc["english"]);
 
  summary["english"] = "Detect Invision Power Top Site List SQL Injection";
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

if (! get_port_state(port) ) exit(0);
if (! can_host_php(port:port) ) exit(0);

function check_dir(path)
{
  req = http_get(item:string(path, "/index.php?offset=[%20Problem%20Here%20]"), port:port);
  res = http_keepalive_send_recv(port:port, data:req);
  if ( res == NULL ) exit(0);
 if (egrep(pattern:"syntax to use near '\[ Problem Here \]", string:res))
 {
  security_hole(port);
  exit(0);
 }
}


foreach dir (cgi_dirs())
{
 check_dir(path:dir);
}

