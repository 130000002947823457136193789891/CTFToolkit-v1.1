#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#
 
if (description) {
  script_id(16339);
  script_version("$Revision: 1.4 $");

  script_cve_id("CAN-2005-0202");
  script_bugtraq_id(12504);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"13671");
    script_xref(name:"FLSA", value:"FEDORA-2005-131");
    script_xref(name:"FLSA", value:"FEDORA-2005-132");
    script_xref(name:"GLSA", value:"GLSA-200502-11");
    script_xref(name:"RHSA", value:"RHSA-2005:136-08");
  }
 
  name["english"] = "Mailman private.py Directory Traversal Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "

The target is running a version of Mailman that might have a directory
traversal vulnerability in Cgi/private.py.  The flaw comes into play
only on web servers that don't strip extraneous slashes from URLs,
such as Apache 1.3.x, and allows a list subscriber, using a specially
crafted web request, to retrieve arbitrary files from the server - any
file accessible by the user under which the web server operates,
including email addresses and passwords of subscribers of any lists
hosted on the server.  For example, if $user and $pass identify a
subscriber of the list $listname@$target, then the following URL :

  http://$target/mailman/private/$listname/.../....///mailman?username=$user&password=$pass

allows access to archives for the mailing list named mailman for which
the user might not otherwise be entitled. 

***** Nessus has determined the vulnerability exists on the target
***** simply by looking at the version number of Mailman installed
***** there.

See also : 
  http://mail.python.org/pipermail/mailman-announce/2005-February/000076.html
  http://lists.netsys.com/pipermail/full-disclosure/2005-February/031562.html

Solution : Upgrade to Mailman 2.1.6b1 or apply the fix referenced in the
first URL above. 

Risk factor : High";
  script_description(english:desc["english"]);

  summary["english"] = "Checks for Mailman private.py Directory Traversal Vulnerability";
  script_summary(english:summary["english"]);

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005 George A. Theall");

  family["english"] = "Remote file access";
  script_family(english:family["english"]);

  script_dependencie("global_settings.nasl", "http_version.nasl", "mailman_detect.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("backport.inc");
include("global_settings.inc");
include("http_func.inc");

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
debug_print("checking for Mailman private.py Directory Traversal Vulnerability on port ", port, ".");

# Web servers to ignore because it's known they strip extra slashes from URLs.
#
# nb: these can be regex patterns.
web_servers_to_ignore = make_list(
  "Apache(-AdvancedExtranetServer)?/2",                      # Apache 2.x
  "Apache.*/.* (Darwin)"
);

# Skip check if the server's type and version indicate it's not a problem,
# unless report paranoia is set high.
banner = get_http_banner(port: port);
if (banner && report_paranoia < 2) {
  banner = get_backport_banner(banner:banner);
  web_server = strstr(banner, "Server:");
  if (web_server) {
    web_server = web_server - strstr(web_server, "\r\n");
    foreach pat (web_servers_to_ignore) {
      if (ereg(string:web_server, pattern:string("^Server:.*", pat))) {
        debug_print("skipping because web server claims to be '", web_server, "'.");
        exit(0);
      }
    }
  }
}

# Check each installed instance, stopping if we find a vulnerability.
installs = get_kb_list(string("www/", port, "/Mailman"));
if (isnull(installs)) exit(0);
foreach install (installs) {
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches)) {
    ver = matches[1];
    dir = matches[2];
    debug_print("checking version ", ver, " under ", dir, ".");

    if (ereg(pattern:"^2\.(0|(1|1\.[1-5]([^0-9]|$)))", string:ver)) {
      security_hole(port);
      exit(0);
    }
  }
}
