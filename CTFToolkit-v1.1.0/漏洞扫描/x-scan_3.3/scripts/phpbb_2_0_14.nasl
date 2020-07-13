#
# (C) Tenable Network Security
#
# 

if (description) {
  script_id(18124);
  script_version("$Revision: 1.4 $");

  script_cve_id("CAN-2005-1290", "CAN-2005-1193");
  script_bugtraq_id(13344, 13345, 13545);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"15919");
  }

  name["english"] = "Multiple vulnerabilities in phpBB 2.0.14 and older";
  script_name(english:name["english"]);
 
  desc["english"] = "
According to its banner, the remote host is running a version of phpBB
that suffers from multiple flaws:

  - A BBCode Input Validation Vulnerability
    The application fails to properly filter for the BBCode
    URL in the 'includes/bbcode.php' script. With a specially-
    crafted URL, an attacker cause arbitrary script code to be 
    executed in a user's browser, possibly even to modify
    registry entries without the user's knowledge.

  - Cross-Site Scripting Vulnerabilities
    The application does not properly sanitize user-supplied input
    to the 'forumname' and 'forumdesc' parameters of the 
    'admin/admin_forums.php' script. By enticing an phpBB 
    administrator to visit a a specially-crafted link, an attacker
    can potentially steal the admin's session cookie or perform
    other attacks.

  - Improper Filtering of HTML Code
    The application does not completely filter user-supplied input
    to the 'u' parameter of the 'profile.php' script or the 
    'highlight' parameter of the 'viewtopic.php' script.

See also : http://castlecops.com/t123194-.html
           http://www.phpbb.com/phpBB/viewtopic.php?f=14&t=288194
Solution : Upgrade to phpBB version 2.0.15 or later.
Risk factor : High";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple vulnerabilities in phpBB 2.0.14 and older";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  family["english"] = "CGI abuses";
  script_family(english:family["english"]);

  script_dependencie("phpbb_detect.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/phpBB"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];
  if (ver =~ "^([01]\..*|2\.0\.([0-9]|1[0-4])([^0-9]|$))") security_hole(port);
}

