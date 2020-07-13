#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#

if (description) {
script_id(14304);
script_bugtraq_id(3276);


# script_cve_id("CVE-MAP-NOMATCH");
# NOTE: no CVE id assigned (gat, August 2004)
  script_version ("$Revision: 1.7 $");
 
  name["english"] = "BasiliX Arbitrary Command Execution Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = '
The target is running at least one instance of BasiliX whose version
number is 1.0.2beta or 1.0.3beta.  In such versions, login.php3 fails to
sanitize user input, which enables a remote attacker to pass in a
specially crafted value for $username with arbitrary commands to be
executed on the target using the permissions of the web server.  
Note that successful exploitation requires 
(1) setup of a imap daemon to authenticate the special $username
(2) knowledge of a valid BasiliX "domain" on the target, and 
(3) passing in additional arguments to instruct BasiliX to use an 
alternate imap daemon. 

For example, if the attacker sets up a special imap daemon on
example.com:143 and knows the target uses the domain "basilix.org", the
following URL would create the file blah.php in the js directory under
the base URL for BasiliX which could later be accessed to display PHP
install / configuration information :

  target/basilix.php3?
    RequestID=LOGIN&
    BSX_TestCookie=1&
    SESSID=1&
    username=blah;echo%20"<?phpinfo();?>">js/blah.php&
    password=blah&
    domain=blah&
    bsx_domains[blah][imap_host]=example.com&
    bsx_domains[blah][imap_port]=143&
    bsx_domains[blah][domain]=basilix.org

***** Nessus has determined the vulnerability exists on the target
***** simply by looking at the version number(s) of BasiliX
***** installed there.

Solution : Upgrade to BasiliX version 1.1.0 or later.
Risk factor : High';
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for Arbitrary Command Execution Vulnerability in BasiliX";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004 George A. Theall");

  family["english"] = "CGI abuses";
  script_family(english:family["english"]);

  script_dependencie("basilix_detect.nasl", "global_settings.nasl");
  script_require_ports("services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("http_func.inc");

host = get_host_name();
port = get_http_port(default:80);
if (debug_level) display("debug: searching for Arbitrary Command Execution vulnerability in BasiliX on ", host, ":", port, ".\n");

if (!get_port_state(port)) exit(0);

# Check each installed instance, stopping if we find a vulnerability.
installs = get_kb_list(string("www/", port, "/basilix"));
if (isnull(installs)) exit(0);
foreach install (installs) {
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches)) {
    ver = matches[1];
    dir = matches[2];
    if (debug_level) display("debug: checking version ", ver, " under ", dir, ".\n");

    if (ereg(pattern:"^1\.0.[23]", string:ver)) {
      security_hole(port);
      exit(0);
    }
  }
}
