#
# (C) Tenable Network Security
#


if (description) {
  script_id(17259);
  script_version("$Revision: 1.1 $");

  script_bugtraq_id(11545);

  script_name(english:"Multiple Vulnerabilities in PHPlist 2.6.3 and older");
  desc["english"] = "
The remote host is running PHPlist, a PHP application which gathers
handles mailing and customer lists.  According to its banner, the
installed version is prone to a slew of bugs which may include
cross-site scripting (XSS), SQL injection, HTML injection, and
possibly others.

Solution : Upgrade to PHPlist 2.6.4 or later.

Risk factor : High";
  script_description(english:desc["english"]);

  script_summary(english:"Detects multiple vulnerabilities in PHPlist 2.6.3 and older");

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencie("find_service.nes", "http_version.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Search for PHPlist in a couple of different locations in addition to
# cgi_dirs() based on googling for "Powered by PHPlist".
dirs = make_list(cgi_dirs());
xtra_dirs = make_array(
  "/phplist", 1,
  "/lists", 1
);
foreach dir (dirs) {
  # Set value to zero if it's already in dirs.
  if (!isnull(xtra_dirs[dir])) xtra_dirs[dir] = 0;
}
foreach dir (keys(xtra_dirs)) {
  # Add it to dirs if the value is still set.
  if (xtra_dirs[dir]) dirs = make_list(dirs, dir);
}
foreach dir (dirs) {
  # Get page for subscribing to a mailing list.
  req = http_get(item:string(dir, "/?p=subscribe&id=1"), port:port);
  res = http_keepalive_send_recv(port:port, data:req);
  if (res == NULL) exit(0);

  # If the main page is from PHPlist...
  if (".poweredphplist" >< res) {

    # Sometimes the version number can be found in a META tag.
    pat = '<meta name="Powered-By" content="PHPlist version (.+)">';
    matches = egrep(pattern:pat, string:res, icase:TRUE);
    foreach match (split(matches)) {
      match = chomp(match);
      ver = eregmatch(pattern:pat, string:match);
      if (!isnull(ver)) {
        ver = ver[1];
        break;
      }
    }
    # Otherwise, try in the "Powered by" line.
    if (isnull(ver)) {
      pat = "powered by .+>phplist</a> v (.+), &copy;";
      matches = egrep(pattern:pat, string:res, icase:TRUE);
      foreach match (split(matches)) {
        match = chomp(match);
        ver = eregmatch(pattern:pat, string:match);
        if (!isnull(ver)) {
          ver = ver[1];
          break;
        }
      }
    }

    # Versions 2.6.3 and older are vulnerable.
    if (ver && ver =~ "^([01].*|2\.[0-5].*|2\.6\.[0-3])") {
      security_hole(port);
      exit(0);
    }
  }
}
