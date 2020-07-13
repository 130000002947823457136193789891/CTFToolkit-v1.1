#
# (C) Tenable Network Security
#

if(description)
{
 script_id(15779);

 script_version("$Revision: 1.5 $");
 name["english"] = "phpBB Detection";
 script_name(english:name["english"]);
 
 desc["english"] = "
This plugin detects if the phpBB bulletin board system is installed
on the remote host and stores its location and version in the KB.

See also : http://www.phpbb.com/
Risk factor : None";
 script_description(english:desc["english"]);
 
 summary["english"] = "Check for phpBB version";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 - 2005 Tenable Network Security");
 
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

function check(dir) {
  req = http_get(item:dir + "/index.php", port:port);
  buf = http_keepalive_send_recv(port:port, data:req);
  if (buf == NULL) exit(0);
  if (buf !~ "Powered by .+phpBB") return(0);

  if (dir == "") dir = "/";

  # Try to grab the version number from the main page.
  #
  # nb: this won't work for versions starting with 2.0.12 but
  #     since we already have index.php we'll try that first.
  pat = "Powered by.*phpBB</a> ([0-9\.]+)";
  matches = egrep(pattern:pat, string:buf, icase:TRUE);
  foreach match (split(matches)) {
    match = chomp(match);
    ver = eregmatch(pattern:pat, string:match);
    if (!isnull(ver)) {
      ver = ver[1];
      break;
    }
  }

  # If still unsuccessful, try to grab it from the changelog.
  if (isnull(ver)) {
    req = http_get(item:dir + "/docs/CHANGELOG.html", port:port);
    buf = http_keepalive_send_recv(port:port, data:req);
    if (buf == NULL) exit(0);

    pat = "<title>phpBB +(.+) +:: Changelog</title>";
    matches = egrep(pattern:pat, string:buf, icase:TRUE);
    foreach match (split(matches)) {
      match = chomp(match);
      ver = eregmatch(pattern:pat, string:match);
      if (!isnull(ver)) {
        ver = ver[1];
        break;
      }
    }
  }

  # Generate report and update KB.
  #
  # nb: even if we don't know the version number, it's still useful 
  #     to know that it's installed and where.
  if (isnull(ver)) {
    exit(0);
    ver = "unknown";
    report = string(
      "An unknown version of phpBB is installed under ", dir, " on the\n",
      "remote host.\n"
    );
  }
  else {
    report = string(
      "phpBB version ", ver, " is installed under ", dir, " on the\n",
      "remote host.\n"
    );
  }
  report = string(
    report,
    "\n",
    "phpBB is a high powered, fully scalable, and highly customizable Open\n",
    "Source bulletin board package with support for a variety of popular\n",
    "database packages.  See http://www.phpbb.com/ for more information.\n",
    "\n",
    "Risk factor : None"
  );
  security_note(data:report, port:port);
  set_kb_item(
    name:string("www/", port, "/phpBB"),
    value:string(ver, " under ", dir)
  );

  # Comment out next line if interested in multiple installs.
  exit(0);
}

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);

foreach dir (make_list("/phpBB", cgi_dirs())) {
 check(dir:dir);
}
