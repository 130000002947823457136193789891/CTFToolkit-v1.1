#
# (C) Tenable Network Security
#
# 


if (description) {
  script_id(18122);
  script_version("$Revision: 1.1 $");

  script_bugtraq_id(13250);

  name["english"] = "WebcamXP Chat Cross-Site Scripting Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
The remote host is running a version of webcamXP, a webcam software
package and integrated web server for Windows, that suffers from an HTML
injection flaw in its chat feature.  An attacker can exploit this flaw
by injecting malicious HTML and script code through the nickname field
to redirect chat users to arbitrary sites, steal authentication cookies,
and the like. 

See also : http://archives.neohapsis.com/archives/fulldisclosure/2005-04/0393.html

Solution : Upgrade to webcamXP version 2.16.478 or later.

Risk factor : Medium";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for cross-site scripting vulnerability in WebcamXP Chat";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");
 
  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  # nb: this particular web server does not seem vulnerable to general XSS
  #     attacks so we don't have a dependency on cross_site_scripting.nasl.
  script_dependencie("find_service.nes", "http_version.nasl");
  script_require_ports("Services/www", 8080);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:8080);
if (!get_port_state(port)) exit(0);
banner = get_http_banner(port:port);
if (!banner || "webcamXP" >!< banner) exit(0);


# A simple alert to display "Nessus was here".
xss = "<script>alert('Nessus was here');</script>";
# nb: the url-encoded version is what we need to pass in.
exss = "%3Cscript%3Ealert('Nessus%20was%20here')%3B%3C%2Fscript%3E";


# Try to exploit the vulnerability.
req = http_get(item:string(dir, "/chat?nickname=", exss), port:port);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
if (res == NULL) exit(0);


# There's a problem if we see our XSS.
if (xss >< res) security_warning(port);
