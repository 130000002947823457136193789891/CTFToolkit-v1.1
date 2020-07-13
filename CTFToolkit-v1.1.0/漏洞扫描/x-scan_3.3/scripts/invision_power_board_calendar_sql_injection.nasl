#
# This script was written by Noam Rathaus
#
# GPLv2
#
# From: advisory@security-corporation.com
# Subject: [SCSA-025] Invision Power Board SQL Injection Vulnerability
# Date: Saturday 03/01/2004 19:11
#
#

if(description)
{
  script_id(11977);
  script_bugtraq_id(9232);
  script_version("$Revision: 1.9 $");
  name["english"] = "Invision Power Board Calendar SQL Injection Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
The remote host is running Invision Power Board - a CGI suite designed 
to set up a bulletin board system on the remote web server.

A vulnerability has been discovered in the sources/calendar.php file
that allows unauthorized users to inject SQL commands.

An attacker may use this flaw to gain the control of the remote database

Solution : Upgrade to the latest version of this software.

See also : http://www.invisionboard.com/download/index.php?act=dl&s=1&id=12&p=1

Risk factor : High";

  script_description(english:desc["english"]);
 
  summary["english"] = "Detect Invision Power Board Calender SQL Injection";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2003 Noam Rathaus");

  family["english"] = "CGI abuses";
  script_family(english:family["english"]);
  script_dependencie("find_service.nes", "http_version.nasl", "invision_power_board_detect.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);

if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Check each installed instance, stopping if we find a vulnerability.
installs = get_kb_list(string("www/", port, "/invision_power_board"));
if (isnull(installs)) exit(0);
foreach install (installs) {
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches)) {
    ver = matches[1];
    dir = matches[2];

    req = http_get(item:string(dir, "/index.php?act=calendar&y=2004&m=1'"), port:port);
    res = http_keepalive_send_recv(port:port, data:req);

    if ( res == NULL ) exit(0);
    find = string("checkdate() expects parameter");
    find2 = string("mySQL query error");

    if (find >< res  ||
       find2 >< res )
    {
      security_hole(port);
      exit(0);
    }
  }
}
