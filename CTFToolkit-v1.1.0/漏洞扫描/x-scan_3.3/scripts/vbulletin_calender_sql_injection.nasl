#
# (C) Tenable Network Security
#
# Ref:
# From:   a1476854@hotmail.com
# Subject: vBulletin Forum 2.3.xx calendar.php SQL Injection
# Date: January 5, 2004 9:32:15 PM CET
# To:   bugtraq@securityfocus.com
#
#

if(description)
{
  script_id(11981);
  script_cve_id("CVE-2004-0036");
  script_bugtraq_id(9360);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"3344");
  }
  script_version("$Revision: 1.6 $");
  name["english"] = "vbulletin calendar SQL Injection Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
The remote host is running the vBulletin calendar, a CGI designed
to set up an online calendar.

A vulnerability has been discovered in the calendar.php file
that allows unauthorized users to inject SQL commands.

An attacker may use this flaw to gain the control of the remote database

Solution : Upgrade to the latest version of this software.
Risk factor : High";

  script_description(english:desc["english"]);
 
  summary["english"] = "Detect vBulletin Calendar SQL Injection";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2004-2005 Tenable Network Security");

  family["english"] = "CGI abuses";
  script_family(english:family["english"]);
  script_dependencie("find_service.nes", "http_version.nasl", "vbulletin_detect.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);

if (!get_port_state(port))exit(0);
if (!can_host_php(port:port))exit(0);

# Test an install.
install = get_kb_item(string("www/", port, "/panews"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
 path = matches[2];
 req = http_get(item:string(path, "/calendar.php?s=&action=edit&eventid=1'"), port:port);
 res = http_keepalive_send_recv(port:port, data:req);

 if ( res == NULL ) exit(0);

 if ( "SELECT allowsmilies,public,userid,eventdate,event,subject FROM calendar_events WHERE eventid = 1'" >< res ) security_hole(port);
}
