#
# This script was written by Noam Rathaus
#
# GPLv2
#
# From: Oliver Karow [Oliver.Karow@gmx.de]
# Subject: Remotely Anywhere Message Injection Vulnerability
# To: bugtraq@securityfocus.com
# Date: Thursday 11/12/2003 12:36
#

if(description)
{
  script_id(11950);
  script_bugtraq_id(9202);
  script_version ("$Revision: 1.6 $");
  name["english"] = "RemotelyAnywhere Cross Site Scripting"; 
  script_name(english:name["english"]);
 
  desc["english"] = "
A vulnerability in RemotelyAnywhere's web interface allows a remote
attacker to inject malicious text into the login screen, this can
be used by an attacker to make the user do things he would otherwise
not do (for example, change his password after a successful login to
some string provided by the malicious text).

Risk factor : Medium";

  script_description(english:desc["english"]);
 
  summary["english"] = "Detect RemotelyAnywhere www css";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2003 Noam Rathaus");
  family["english"] = "CGI abuses : XSS";
  script_family(english:family["english"]);
  script_dependencie("find_service.nes", "http_version.nasl");
  script_require_ports("Services/www", 2000,2001);
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:2001);
if (! port) exit(0);

banner = get_http_banner(port : port);
if (! banner) exit(0);

# display("banner: ", banner, "\n");

if (ereg(pattern:"Server: *RemotelyAnywhere", string:banner))
{
  req = http_get(item:"/default.html?logout=asdf&reason=Please%20set%20your%20password%20to%20ABC123%20after%20login", port:port);
  res = http_keepalive_send_recv(data:req, port:port, bodyonly:1);
  if ( res == NULL ) exit(0);
#  display("req: ", req, "\n");

  if ("Please set your password to ABC123 after login" >< res)
  {
   security_note(port);
  }
}
