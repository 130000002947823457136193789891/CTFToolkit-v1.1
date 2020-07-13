#
# This script was written by Noam Rathaus
#
# GPLv2
#
# From: JeiAr [security@gulftech.org]
# Subject: Aardvark Topsites 4.1.0 Vulnerabilities
# Date: Tuesday 16/12/2003 04:58

if(description)
{
  script_id(11957);
  script_bugtraq_id(9231);
  script_version ("$Revision: 1.5 $");
  name["english"] =  "Aardvark Topsites Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
Aardvark Topsites is a popular free PHP Topsites script.
Multiple vulnerabilities have been found in the product allowing remote 
attacker to disclosure sensitive information about the server and inject 
malicious SQL statements.

Solution : Upgrade to version 4.1.1 or newer.
Risk factor : Medium";

  script_description(english:desc["english"]);
 
  summary["english"] = "Detect Aardvark Topsites version";
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

if ( ! can_host_php(port:port) ) exit(0);

function check_dir(path)
{
  req = http_get(item:string(path, "/index.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req);
  if ( res == NULL ) exit(0);
  if (egrep(pattern:"Aardvark Topsites PHP.* (4\.1\.0|4\.0\.|[0-3]\..*)", string:res))
  {
   security_warning(port);
   exit(0);
  }
}

foreach dir (cgi_dirs())
{
 check_dir(path:dir);
}

