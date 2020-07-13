#
# (C) Tenable Network Security
#

if(description) {
  script_id(17202);
  script_version("$Revision: 1.1 $");

  script_cve_id("CAN-2005-0477");
  script_bugtraq_id(12607);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"14004");
    script_xref(name:"OSVDB", value:"14005");
  }

  name["english"] = "Invision Power Board COLOR SML Tag Script Injection Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
Invision Power Board version 1.3.1 FINAL (and possibly earlier
versions) reportedly does not sufficiently sanitize the 'COLOR' SML
tag.  A remote attacker may exploit this vulnerability by adding a
specially-crafted 'COLOR' tag with arbitrary Javascript to any
signature or post on an Invision board.  That Javascript will later be
executed in the context of users browsing that forum, which may enable
an attacker to steal cookies or misrepresent site content. 

***** Nessus has determined the vulnerability exists on the target
***** simply by looking at the version number of Invision Power
***** Board installed there.

Solution : Upgrade to a later version of Invision Power Board.
Risk factor : Medium";
  script_description(english:desc["english"]);
 
  summary["english"] = "Detect Invision Power Board COLOR SML Tag Script Injection";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  family["english"] = "CGI abuses : XSS";
  script_family(english:family["english"]);

  script_dependencie("find_service.nes", "http_version.nasl", "invision_power_board_detect.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);


# Check each installed instance, stopping if we find a vulnerability.
installs = get_kb_list(string("www/", port, "/invision_power_board"));
if (isnull(installs)) exit(0);
foreach install (installs) {
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches)) {
    ver = matches[1];
    # nb: the BID isn't clear on this, but we'll treat lesser versions 
    #     as vulnerable as well.
    if ( ver =~ "^1\.(1|2|3.0|3\.1)" ) {
      security_warning(port);
      exit(0);
    }
  }
}
