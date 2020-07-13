#
# (C) Tenable Network Security
#
# From: "JvdR" <thewarlock@home.nl>
# To: <bugtraq@securityfocus.com>
# Subject: Multiple Vulnerabilities in Invision Power Board v1.3.1 Final.
# Date: Tue, 8 Jun 2004 16:53:11 +0200
#

if(description)
{
  script_id(12268);
  script_bugtraq_id(10511);
  script_version("$Revision: 1.3 $");
  name["english"] = "Invision Power Board ssi.php SQL Injection Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
The remote host is running Invision Power Board - a CGI suite designed 
to set up a bulletin board system on the remote web server.

A vulnerability has been discovered in the ssi.php file
that allows unauthorized users to inject SQL commands.

An attacker may use this flaw to gain the control of the remote database

Solution : Upgrade to the latest version of this software.
Risk factor : High";

  script_description(english:desc["english"]);
 
  summary["english"] = "Detect Invision Power Board ssi.php SQL Injection";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2004 - 2005 Tenable Network Security");

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

    req = http_get(item:string(dir, "/ssi.php?a=out&type=xml&f=0)'"), port:port);
    res = http_keepalive_send_recv(port:port, data:req);

    if ( res == NULL ) exit(0);
    if ( "AND t.approved=1 ORDER BY t.last_post" >< res )
    {
      security_hole(port);
      exit(0);
    }
  }
}
