#
# (C) Tenable Network Security
#
# 

if (description) {
  script_id(17301);
  script_version("$Revision: 1.4 $");

  script_cve_id(
    "CAN-2005-0659",
    "CAN-2005-0673"
  );
  script_bugtraq_id(12736, 13028, 13030);

  name["english"] = "Multiple vulnerabilities in phpBB 2.0.13 and older";
  script_name(english:name["english"]);
 
  desc["english"] = "
According to its banner, the remote host is running a version of phpBB
that suffers from multiple flaws:

  - A Path Disclosure Vulnerability
    A remote attacker can cause phpBB to reveal its installation
    path via a direct request to the script 'db/oracle.php'.

  - A Cross-Site Scripting Vulnerability
    The application does not properly sanitize user input before
    using it in 'privmsg.php' and 'viewtopic.php'.

  - A Privilege Escalation Vulnerability
    In 'session.php' phpBB resets the 'user_id' value when an 
    autologin fails; it does not, however, reset the 'user_level' 
    value, which remains as the account that failed the autologin.
    Since the software uses the 'user_level' paramater in some 
    cases to control access to privileged functionality, this flaw
    allows an attacker to view information, and possibly even 
    perform tasks, normally limited to administrators. 

  - SQL Injection Vulnerabilities
    The DLMan Pro and LinksLinks Pro mods, if installed, reportedly 
    fail to properly sanitize user input to the 'file_id' parameter
    of the 'dlman.php' script and the 'id' parameter of the
    'links.php' script respectively before using it in an SQL 
    query. This may allow an attacker to pass malicious input
    to database queries.

Solution : Upgrade to a version after phpBB 2.0.13 when it becomes
available and disable the DLMan Pro and LinksLinks Pro mods. 

Risk factor : Medium";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple vulnerabilities in phpBB 2.0.13 and older";
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
  if (ver =~ "^([01]\..*|2\.0\.([0-9]|1[0-3])([^0-9]|$))") security_hole(port);
}
