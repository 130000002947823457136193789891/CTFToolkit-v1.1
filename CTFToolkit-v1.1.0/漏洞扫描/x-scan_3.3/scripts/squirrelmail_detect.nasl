#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#


# NB: I define the script description here so I can later modify
#     it with the version number and install directory.
  desc["english"] = "
This script detects whether the remote host is running SquirrelMail and
extracts version numbers and locations of any instances found. 

SquirrelMail is a PHP-based webmail package that provides access to mail
accounts via POP3 or IMAP. See http://www.squirrelmail.org/ for more
information. 

Risk factor : None";


if (description) {
  script_id(12647);
  script_version("$Revision: 1.4 $");
 
  name["english"] = "SquirrelMail Detection";
  script_name(english:name["english"]);
 
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for the presence of SquirrelMail";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004 George A. Theall");

  family["english"] = "General";
  script_family(english:family["english"]);

  script_dependencie("global_settings.nasl", "http_version.nasl", "no404.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

host = get_host_name();
port = get_http_port(default:80);
if (debug_level) display("debug: looking for SquirrelMail on ", host, ":", port, ".\n");

if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);
if (get_kb_item("www/no404/" + port)) exit(0);

# Search for SquirrelMail in a couple of different locations.
#
# NB: Directories beyond cgi_dirs() come from a Google search - 
#     'intitle:login squirrelmail' - and represent the more popular
#     installation paths currently. Still, cgi_dirs() should catch
#     the directory if its referenced elsewhere on the target.
dirs = make_list("", "/squirrelmail", "/webmail", "/mail", "/sm", cgi_dirs());
foreach dir (dirs) {
  # Search in a couple of different pages.
  files = make_list(
    "/src/login.php", "/src/compose.php", "/ChangeLog", "/ReleaseNotes"
  );
  foreach file (files) {
    if (debug_level) display("debug: checking ", dir, file, "...\n");

    # Get the page.
    req = http_get(item:string(dir, file), port:port);
    res = http_keepalive_send_recv(port:port, data:req);
    if (res == NULL) exit(0);           # can't connect
    if (debug_level) display("debug: res =>>", res, "<<\n");

    if (egrep(string:res, pattern:"^HTTP/.* 200 OK")) {
      # Specify pattern used to identify version string.
      if (file == "/src/login.php" || file == "/src/compose.php") {
        pat = "<SMALL>SquirrelMail version (.+)<BR";
      }
      else if (file == "/ChangeLog") {
        pat = "^Version (.+) - [0-9]";
      }
      # nb: this first appeared in 1.2.0 and isn't always accurate.
      else if (file == "/ReleaseNotes") {
        pat = "Release Notes: SquirrelMail (.+) *\*";
      }
      # - someone updated files but forgot to add a pattern???
      else {
        if (debug_level) display("Don't know how to handle file '", file, "'!\n");
        exit(1);
      }

      # Get the version string.
      if (debug_level) display("debug: grepping results for =>>", pat, "<<\n");
      matches = egrep(pattern:pat, string:res, icase:TRUE);
      foreach match (split(matches)) {
        match = chomp(match);
        if (debug_level) display("debug: grepping >>", match, "<< for =>>", pat, "<<\n");
        ver = eregmatch(pattern:pat, string:match, icase:TRUE);
        if (ver == NULL) break;
        ver = ver[1];
        if (debug_level) display("debug: SquirrelMail version =>>", ver, "<<\n");

        # Success!
        set_kb_item(
          name:string("www/", port, "/squirrelmail"),
          value:string(ver, " under ", dir)
        );
        installations[dir] = ver;
        ++installs;

        # nb: only worried about the first match.
        break;
      }
      # nb: if we found an installation, stop iterating through files.
      if (installs) break;
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
    info = string("SquirrelMail ", ver, " was detected on the remote host under the path ", dir, ".");
  }
  else {
    info = string(
      "Multiple instances of SquirrelMail were detected on the remote host:\n",
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
