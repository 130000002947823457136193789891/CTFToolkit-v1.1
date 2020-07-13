#
# (C) Tenable Network Security
#


if (description) {
  script_id(18504);
  script_version("$Revision: 1.2 $");

  script_cve_id("CAN-2005-1769", "CAN-2005-2095");
  script_bugtraq_id(13973, 14254);
 
  name["english"] = "SquirrelMail < 1.45 Multiple Vulnerabilities";
  script_name(english:name["english"]);

  desc["english"] = "
The version of SquirrelMail installed on the remote host is prone to
multiple flaws :

  - Multiple Cross-Site Scripting Vulnerabilities
    Using a specially-crafted URL or email message, an 
    attacker may be able to exploit these flaws, stealing 
    cookie-based session identifiers and thereby hijacking
    SquirrelMail sessions.

  - Post Variable Handling Vulnerabilities
    Using specially-crafted POST requests, an attacker may
    be able to set random variables in the file
    'options_identities.php', which could lead to accessing
    other user's preferences, cross-site scripting attacks,
    and writing to arbitrary files.

See also : http://sourceforge.net/mailarchive/forum.php?thread_id=7519477&forum_id=1988
Solution : Upgrade to SquirrelMail 1.45 or later.
Risk factor : Medium";
  script_description(english:desc["english"]);

  summary["english"] = "Checks for multiple vulnerabilities in SquirrelMail < 1.45";
  script_summary(english:summary["english"]);

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_require_ports("Services/www", 80);
  script_dependencies("squirrelmail_detect.nasl");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/squirrelmail"));
if (isnull(install)) exit(1);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  # There's a problem if the version is < 1.45.
  if (ver =~ "^1\.([0-3]\.|4\.[0-4]([^0-9]|$))") {
    security_warning(port);
  }
}
