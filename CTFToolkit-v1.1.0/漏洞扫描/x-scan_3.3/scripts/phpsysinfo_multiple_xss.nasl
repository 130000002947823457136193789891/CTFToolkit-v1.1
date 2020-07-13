#
# (C) Tenable Network Security
#


if (description) {
  script_id(17610);
  script_version("$Revision: 1.1 $");
  script_bugtraq_id(12887);

  script_name(english:"PHPSysInfo Multiple Cross-Site Scripting Vulnerabilities");
  desc["english"] = "
The remote host is running PHPSysInfo, a PHP script which parses the /proc
entries on Linux systems and displays them in HTML.

The version of phpSysInfo installed on the remote host is affected by
multiple cross-site scripting vulnerabilities due to its failure to
sanitize user-input to the 'sensor_program' parameter of 'index.php'
and the 'text[language]', 'text[template]', and 'VERSION' parameters
of 'system_footer.php'.  If PHP's register_globals setting is enabled
(it's not recommended but fairly common), a remote attacker can
exploit these flaws to have arbitrary script rendered in the browser
of a user in the context of the affected web site. 

See also : http://www.securityfocus.com/archive/1/394086

Solution : Upgrade to a version of phpSysInfo greater than 2.3 when it
becomes available. 

Risk factor : Medium";
  script_description(english:desc["english"]);

  script_summary(english:"Checks for multiple cross-site scripting vulnerabilities in PHPSysInfo");

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencie("find_service.nes", "http_version.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);
if (get_kb_item("www/" + port + "/generic_xss")) exit(0);


# Check various directories for phpSysInfo.
foreach dir (cgi_dirs()) {
  # A simple alert to display "Nessus was here".
  xss = "Error: <script>alert('Nessus was here');</script>";
  # nb: the url-encoded version is what we need to pass in.
  exss = "%3Cscript%3Ealert('Nessus%20was%20here')%3B%3C%2Fscript%3E";
  req = http_get(
    item:string(
      dir, 
      "/index.php?",
      "sensor_program=", exss
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
  if (res == NULL) exit(0);

  # If we see our XSS, there's a problem.
  if (xss >< res) {
    security_warning(port);
    exit(0);
  }
}
