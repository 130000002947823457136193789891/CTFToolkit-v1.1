#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#

if (description) {
script_id(14307);
script_bugtraq_id(10666);


# script_cve_id("CVE-MAP-NOMATCH");
# NOTE: no CVE id assigned (gat, August 2004)
  script_version ("$Revision: 1.8 $"); 
  name["english"] = "BasiliX Content-Type XSS Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
The target is running at least one instance of BasiliX whose version
number is 1.1.1 or lower.  Such versions are vulnerable to a
cross-scripting attack whereby an attacker may be able to cause a victim
to unknowingly run arbitrary Javascript code simply by reading a MIME
message with a specially crafted Content-Type header. 

For information about the vulnerability, including exploits, see :

  - http://www.rs-labs.com/adv/RS-Labs-Advisory-2004-2.txt
  - http://www.rs-labs.com/adv/RS-Labs-Advisory-2004-1.txt

***** Nessus has determined the vulnerability exists on the target
***** simply by looking at the version number(s) of BasiliX
***** installed there.

Solution : Upgrade to BasiliX version 1.1.1 fix1 or later.
Risk factor : Medium";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for Content-Type XSS Vulnerability in BasiliX";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004 George A. Theall");

  family["english"] = "CGI abuses : XSS";
  script_family(english:family["english"]);

  script_dependencie("basilix_detect.nasl", "global_settings.nasl");
  script_require_ports("services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("http_func.inc");

host = get_host_name();
port = get_http_port(default:80);
if (debug_level) display("debug: searching for Content-Type XSS vulnerability in BasiliX on ", host, ":", port, ".\n");

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

    if (ereg(pattern:"^(0\..*|1\.0.*|1\.1\.(0|1))$", string:ver)) {
      security_warning(port);
      exit(0);
    }
  }
}
