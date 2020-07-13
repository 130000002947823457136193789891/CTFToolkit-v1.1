#
# This script was written by Noam Rathaus
#
# GPLv2
#
# From: "Rafel Ivgi, The-Insider" <theinsider@012.net.il>
# Subject: FlexWATCH-Webs 2.2 (NTSC) Authorization Bypass
# Date: 2004-02-24 16:45
#

if(description)
{
  script_id(12078);
  script_cve_id("CAN-2003-1160");
  script_bugtraq_id(8942);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"2842");
  }
  script_version("$Revision: 1.3 $");
  name["english"] = "FlexWATCH Authentication Bypassing";
  script_name(english:name["english"]);
 
  desc["english"] = "
There is a vulnerability in the current version of FlexWATCH that allows an 
attacker to access administrative sections without being required to 
authenticate.

An attacker may use this flaw to gain the list of user accounts on this system
and the ability to reconfigure this service.

This is done by adding an additional '/' at the begining of the URL.

Solution : None at this time - filter incoming traffic to this port
Risk factor : High";

  script_description(english:desc["english"]);
 
  summary["english"] = "Detect FlexWATCH Authentication Bypassing";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2004 Noam Rathaus");

  family["english"] = "General";
  script_family(english:family["english"]);
  script_dependencie("find_service.nes", "http_version.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);


req = http_get(item:"//admin/aindex.htm", port:port);
res = http_keepalive_send_recv(port:port, data:req);
if ( res == NULL ) exit(0);
find = string("GoAhead-Webs");
find2 = string("admin.htm");
find3 = string("videocfg.htm");
if ( find >< res && find2 >< res && find3 >< res )
{
  security_hole(port);
  exit(0);
}

