#
# (C) Tenable Network Security
#


if (description) {
  script_id(17247);
  script_version("$Revision: 1.2 $");

  script_cve_id("CAN-2005-0632");
  script_bugtraq_id(12696);

  script_name(english:"PHPNews auth.php Remote File Include Vulnerability");

  desc["english"] = "
The remote host is running a version of PHPNews, an open source news
application, that has a remote file include vulnerability in the script
'auth.php'.  By leveraging this flaw, a attacker can cause arbitrary PHP
code to be executed on the remote host using the permissions of the web
server user. 

Solution : Upgrade to PHPNews 1.2.5 or greater or make sure PHP's
           'register_globals' and 'allow_url_fopen' settings are disabled.
Risk factor : High";
  script_description(english:desc["english"]);
 
  summary["english"] = "Detects remote file include vulnerability in auth.php in PHPNews";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security.");

  script_dependencie("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Search for PHPNews in a couple of different locations in addition to
# cgi_dirs() based on googling for "PHPNews Login".
dirs = make_list(cgi_dirs());
xtra_dirs = make_array(
  "/phpnews", 1,
  "/news", 1
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
  req = http_get(item:string(dir, "/index.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req);
  if (res == NULL) exit(0);

  # If the main page is from PHPNews...
  if (res =~ '<link href="phpnews_package.css"') {

    # Try the exploit by grabbing the site's PHPNews phpnews_package.css --
    # it's won't show up in someone else's logs and by itself is harmless.
    exploit = string("/auth.php?path=http://", get_host_name(), dir, "/phpnews_package.css%00");
    req = http_get(item:string(dir, exploit), port:port);
    res = http_keepalive_send_recv(port:port, data:req);
    if (res == NULL) exit(0);

    # If it looks like we got a stylesheet, there's a problem.
    if (egrep(pattern:"a:link {", string:res, icase:TRUE)) {
      security_hole(port);
      exit(0);
    }
  }
}
