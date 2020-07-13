#
# (C) Tenable Network Security
#


if (description) {
  script_id(17634);
  script_version("$Revision: 1.2 $");

  script_cve_id("CAN-2005-0896");
  script_bugtraq_id(12900);

  script_name(english:"PHPMyDirectory review.php Multiple Cross-Site Scripting Vulnerabilities");

  desc["english"] = "
The version of phpMyDirectory installed on the remote host suffers
from multiple cross-site scripting vulnerabilities due to its failure
to sanitize user-input to its 'review.php' script through various
parameters.  A remote attacker can exploit these flaws to steal
cookie-based authentication credentials and perform other such
attacks. 

Solution : Upgrade to phpMyDirectory version 10.1.6 or newer.
Risk factor : Low";
  script_description(english:desc["english"]);

  script_summary(english:"Checks for multiple cross-site scripting vulnerabilities in PHPMyDirectory's review.php");

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencie("cross_site_scripting.nasl", "find_service.nes", "http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);
if (get_kb_item("www/"+port+"/generic_xss")) exit(0);


# A simple alert to display "Nessus was here".
xss = "<script>alert('Nessus was here');</script>";
# nb: the url-encoded version is what we need to pass in.
exss = "%3Cscript%3Ealert('Nessus%20was%20here')%3B%3C%2Fscript%3E";


# Check various directories for PHPMyDirectory.
foreach dir (cgi_dirs()) {
  # Try to exploit the vulnerability with our XSS.
  req = http_get(
    item:string(
      dir, "/review.php?",
      "id=1&",
      "cat=&",
      'subcat=%22%3E' , exss
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if ...
  if (
    # it's from phpMyDirectory and...
    ('<META name="copyright" CONTENT="Copyright, phpMyDirectory.com.' >< res) &&
    # we see our exploit
    (xss >< res)
  ) {
    security_warning(port);
    exit(0);
  }
}
