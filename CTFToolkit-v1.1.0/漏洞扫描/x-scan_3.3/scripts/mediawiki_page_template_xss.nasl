#
# (C) Tenable Network Security
#
# 

if (description) {
  script_id(18430);
  script_version("$Revision: 1.2 $");

  script_cve_id("CAN-2005-1888");
  script_bugtraq_id(13861);

  name["english"] = "MediaWiki Page Template Cross-Site Scripting Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
The remote host seems to be running MediaWiki, a wiki web application
written in PHP. 

The remote version of this software is vulnerable to cross-site
scripting attacks because of its failure to sanitize input passed to
certain HTML attributes by including a template inside a style
directive when editing an entry.  An attacker can leverage this flaw
to inject arbitrary HTML and script code to be executed by a user's
browser within the context of an affected site. 

***** Nessus has determined the vulnerability exists on the remote
***** host simply by checking the version number of MediaWiki
***** installed there.

See also : http://bugzilla.wikimedia.org/show_bug.cgi?id=2304
Solution : Upgrade to MediaWiki 1.3.13 or later if using 1.3 legacy series;
           otherwise, switch to 1.4.5 or later.
Risk factor : Low";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for page template cross-site scripting vulnerability in MediaWiki";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencie("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# For each CGI directory...
foreach dir (cgi_dirs()) {
  # Try to get MediaWiki's version number.
  req = http_get(item:string(dir, "/index.php?title=Special:Version"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  if (res == NULL) exit(0);

  # If it looks like MediaWiki, grab its version number.
  #
  # nb: this doesn't catch the really old versions (MediaWiki-stable 
  #     20031117 and older), but they no longer appear to be deployed.
  pat = ">MediaWiki</a>.+: ([0-9]+\.[0-9]+.*)";
  if (egrep(string:res, pattern:pat, icase:TRUE)) {
    matches = egrep(pattern:pat, string:res, icase:TRUE);
    foreach match (split(matches)) {
      match = chomp(match);
      ver = eregmatch(pattern:pat, string:match);
      if (!isnull(ver)) {
        ver = ver[1];
        iver = split(ver, sep:'.', keep:FALSE);

        # Check for a vulnerable version.
        if (
          int(iver[0]) == 0 ||
          (
            int(iver[0]) == 1 && 
            (
              int(iver[1]) < 3 ||
              (int(iver[1]) == 3 && int(iver[2]) < 13) ||
              (int(iver[1]) == 4 && int(iver[2]) < 5) ||
              (int(iver[1]) == 5 && isnull(iver[2]) && ver =~ "alpha1")
            )
          )
        ) {
          security_note(port);
          exit(0);
        }
        break;
      }
    }
  }
}
