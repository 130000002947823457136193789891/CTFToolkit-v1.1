#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#

if (description) {
  script_id(14218);
  script_version("$Revision: 1.9 $");

  script_cve_id("CAN-2002-1708");
  script_bugtraq_id(5060);

  name["english"] = "BasiliX Message Content Script Injection Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
The target is running at least one instance of BasiliX whose version
number is 1.1.0 or lower.  Such versions are vulnerable to
cross-scripting attacks since they do not filter HTML tags when showing
a message.  As a result, an attacker can include Javascript code in a
message and have that code executed by the user's browser when it is
viewed. 

***** Nessus has determined the vulnerability exists on the target
***** simply by looking at the version number(s) of BasiliX
***** installed there.

Solution : Upgrade to BasiliX version 1.1.1 or later.
Risk factor : Medium";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for Message Content Script Injection Vulnerability in BasiliX";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2004 George A. Theall");

  script_dependencie("basilix_detect.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("http_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/basilix"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  if (ver =~ "^(0\..*|1\.(0.*|1\.0))$") {
    security_warning(port);
    exit(0);
  }
}
