#
# (C) Tenable Network Security
#


if (description) {
  script_id(18495);
  script_version("$Revision: 1.3 $");

  script_cve_id("CAN-2005-2002");
  script_bugtraq_id(13966, 14117, 14119);

  name["english"] = "Mambo Open Source < 4.5.2.3 Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
The installed version of Mambo Open Source on the remote host suffers from
multiple flaws :

  - Session ID Spoofing Vulnerability
    An unspecified flaw in the script 'administrator/index3.php'
    can be exploited to spoof session IDs.

  - Local file Disclosure Vulnerability
    The 'includes/DOMIT/testing_domit.php' script may be used
    to read the contents of local files such as Mambo's
    configuration file, which holds database credentials.

  - A SQL Injection Vulnerability
    The application fails to properly sanitize user-supplied 
    input to the 'user_rating' parameter of the 
    'components/com_content/content.php' script before using 
    it in SQL statements.

  - Multiple Unspecified Injection Vulnerabilities
    Various class 'check' methods fail to properly
    sanitize input, although it's unknown precisely
    what dangers these flaws present.

See also : http://lists.grok.org.uk/pipermail/full-disclosure/2005-June/034575.html
           http://mamboforge.net/frs/download.php/6153/CHANGELOG
Solution : Upgrade to Mambo version 4.5.2.3 or greater.
Risk factor : High";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple vulnerabilities in Mambo Open Source < 4.5.2.3";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencie("mambo_detect.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/mambo_mos"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Try to exploit the SQL injection flaw.
  #
  # nb: randomize CID to avoid already voted problems.
  cid = rand() % 100;
  req = http_get(
    item:string(
      dir, "/index.php?",
      "option=com_content&",
      "task=vote&",
      "id=1&",
      "Itemid=1&",
      "cid=", cid, "&",
      # this just produces a syntax error in a vulnerable version.
      "user_rating=1'", SCRIPT_NAME
    ),
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if we see a syntax error mentioning this plugin.
  if (
    "DB function failed with error number 1064" >< res &&
    string("right syntax to use near '", SCRIPT_NAME, "', '") >< res
  ) {
    security_hole(port);
    exit(0);
  }
}
