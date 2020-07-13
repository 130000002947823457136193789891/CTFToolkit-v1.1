#
# (C) Tenable Network Security
#

  desc["english"] = "
This script detects whether the remote host is running phpWebSite and
extracts version numbers and locations of any instances found. 

phpWebSite is a website content management system written in PHP.  See
http://phpwebsite.appstate.edu/ for more information.";


if (description) {
  script_id(17222);
  script_version("$Revision: 1.2 $");
 
  name["english"] = "phpWebSite Detection";
  script_name(english:name["english"]);
 
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for the presence of phpWebSite";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  family["english"] = "CGI abuses";
  script_family(english:family["english"]);

  script_dependencie("global_settings.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Search for phpWebSite in a couple of different locations in addition to 
# cgi_dirs() based on googling for 'powered by phpwebsite'.
dirs = make_list(cgi_dirs());
xtra_dirs = make_array(
  "/phpwebsite", 1,
  "", 1
);
foreach dir (dirs) {
  # Set value to zero if it's already in dirs.
  if (!isnull(xtra_dirs[dir])) xtra_dirs[dir] = 0;
}
foreach dir (keys(xtra_dirs)) {
  # Add it to dirs if the value is still set.
  if (xtra_dirs[dir]) dirs = make_list(dirs, dir);
}

installs = 0;
foreach dir (dirs) {
  req = http_get(item:string(dir, "/index.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req);
  if ( res == NULL ) exit(0);

  # If it looks like phpWebSite...
  if ( egrep(pattern:'(meta name="generator" content="phpWebSite"|powered by.+phpWebSite)', string:res, icase:TRUE)  ) {
    # Try to grab the version number from the changelog.
    req = http_get(item:string(dir, "/docs/CHANGELOG.txt"), port:port);
    res = http_keepalive_send_recv(port:port, data:req);
    if ( res == NULL ) exit(0);

    if ( dir == "" ) dir = "/";
    pat = "phpWebSite-(.+) \(";
    matches = egrep(pattern:pat, string:res);
    foreach match (split(matches)) {
      match = chomp(match);
      ver = eregmatch(pattern:pat, string:match);
      if (ver == NULL) break;
      ver = ver[1];

      # Success!
      set_kb_item(
        name:string("www/", port, "/phpwebsite"), 
        value:string(ver, " under ", dir)
      );
      installations[dir] = ver;
      ++installs;

      # nb: only worried about the first match.
      break;
    }
  }
  # Scan for multiple installations only if "Thorough Tests" is checked.
  if (installs && !thorough_tests) break;
}


# Report any instances found unless Report verbosity is "Quiet".
if (installs && report_verbosity > 0) {
  if (installs == 1) {
    foreach dir (keys(installations)) {
      # empty - just need to set 'dir'.
    }
    info = string("phpWebSite ", ver, " was detected on the remote host under\nthe path ", dir, ".");
  }
  else {
    info = string(
      "Multiple instances of phpWebSite were detected on the remote host:\n",
      "\n"
    );
    foreach dir (keys(installations)) {
      info = info + string("    ", installations[dir], ", installed under ", dir, "\n");
    }
    info = chomp(info);
  }

  desc = ereg_replace(
    string:desc["english"],
    pattern:"This script[^\.]+\.", 
    replace:info
  );
  security_note(port:port, data:desc);
}
