#
# This script was written by Noam Rathaus
#
# GPLv2
#
# From: JeiAr [security@gulftech.org]
# Subject: osCommerce Malformed Session ID XSS Vuln
# Date: Wednesday 17/12/2003 19:59
#
#

if(description)
{
  script_id(11958);
  script_bugtraq_id(9238);
  script_version("$Revision: 1.8 $");
  name["english"] = "osCommerce Malformed Session ID XSS Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
osCommerce is an online shop e-commerce solution under on going development 
by the open source community. Its feature packed out-of-the-box installation
allows store owners to setup, run, and maintain their online stores with 
minimum effort and with absolutely no costs or license fees involved.

osCommerce is vulnerable to a XSS flaw. The flaw can be exploited when a 
malicious user passes a malformed session ID to URI.

Solution :
This is the response from the developer. To fix the issue, the $_sid parameter
needs to be wrapped around tep_output_string() in the tep_href_link() function
defined in includes/functions/html_output.php.

Before:
if (isset($_sid)) {
$link .= $separator . $_sid;
}

After:
if (isset($_sid)) {
$link .= $separator . tep_output_string($_sid);
}

osCommerce 2.2 Milestone 3 will redirect the user to the index page when 
a malformed session ID is used, so that a new session ID can be generated.

Risk factor : Medium";

  script_description(english:desc["english"]);
 
  summary["english"] = "Detect osCommerce Malformed Session ID XSS";
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

if (!get_port_state(port)) exit(0);

quote = raw_string(0x22);

function check_dir(path)
{
 req = http_get(item:string(path, "?osCsid=%22%3E%3Ciframe%20src=foo%3E%3C/iframe%3E"), port:port);
#  display("req: ", req, "\n");

 res = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
#  display("res: ", res, "\n");

 if ( res == NULL ) exit(0);
 find = string("\\?osCsid=", quote, "><iframe src=foo></iframe>");

 if (egrep(pattern:find, string:res))
 {
  security_warning(port);
  exit(0);
 }
}

foreach dir (cgi_dirs()) check_dir(path:dir);
