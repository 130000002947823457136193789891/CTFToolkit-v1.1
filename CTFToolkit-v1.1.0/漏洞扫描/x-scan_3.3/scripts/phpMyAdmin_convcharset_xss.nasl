#
# (C) Tenable Network Security
#

if (description) {
  script_id(17689);
  script_version("$Revision: 1.2 $");

  script_cve_id("CAN-2005-0992");
  script_bugtraq_id(12982);

  name["english"] = "PHPMyAdmin convcharset Cross-Site Scripting Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
The installed version of phpMyAdmin suffers from a cross-site
scripting vulnerability due to its failure to sanitize user input to
the 'convcharset' parameter of the 'index.php' script.  A remote
attacker may use these vulnerabilities to cause arbitrary code to be
executed in a user's browser to steal authentication cookies and the
like. 

Solution : Upgrade to phpMyAdmin 2.6.2-rc1 or later.
Risk factor : Medium";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for convcharset cross-site scripting vulnerability in PHPMyAdmin";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");
 
  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencie("cross_site_scripting.nasl", "phpMyAdmin_detect.nasl");
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


# Test an install.
install = get_kb_item(string("www/", port, "/phpMyAdmin"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Try to exploit the vulnerability with our XSS.
  req = http_get(
    item:string(
      dir, "/index.php?",
      "pma_username=&",
      "pma_password=&",
      "server=1&",
      "lang=en-iso-8859-1&",
      "convcharset=%5C%22%3E", exss
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

  # There's a problem if we see our XSS.
  if (xss >< res) security_warning(port);
}
