#
# (C) Tenable Network Security
#
# 

if (description) {
  script_id(18612);
  script_version("$Revision: 1.1 $");

  script_bugtraq_id(14127);

  name["english"] = "osTicket <= 1.3.1 Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
The version of osTicket installed on the remote host suffers from
several vulnerabilities, including:

  - A Local File Include Vulnerability
    The application fails to sanitize user-supplied input
    to the 'inc' parameter in the 'view.php' script. After
    authentication, an attacker can exploit this flaw to
    run arbitrary PHP code found in files on the remote
    host provided PHP's 'register_globals' setting is 
    enabled.

  - A SQL Injection Vulnerabilitie
    An authenticated attacker can affect SQL queries via
    POST queries due to a failure of the application to
    filter input to the 'ticket' variable in the 
    'class.ticket.php' code library.

See also : http://www.securityfocus.com/archive/1/403990/30/0/threaded
Solution : Unknown at this time.
Risk factor : Medium";
  script_description(english:desc["english"]);

  summary["english"] = "Checks for multiple vulnerabilities in osTicket <= 1.3.1";
  script_summary(english:summary["english"]);

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencie("osticket_detect.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/osticket"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  # Check the version number -- both flaws require authentication.
  #
  # nb: versions <= 1.3.1 are vulnerable.
  if (ver  =~ "^(0\.|1\.([01]\.|2\.[0-7]|3\.[01]))") {
    security_warning(port:port, data:desc);
    exit(0);
  }
}

