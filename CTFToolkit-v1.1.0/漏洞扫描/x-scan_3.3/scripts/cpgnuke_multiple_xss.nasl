#
# (C) Tenable Network Security
#


if (description) {
  script_id(17647);
  script_version("$Revision: 1.1 $");

  script_cve_id("CAN-2005-0914");
  script_bugtraq_id(12930);

  script_name(english:"CPG Dragonfly Multiple Cross-Site Scripting Vulnerabilities");
  desc["english"] = "
The version of CPG Dragonfly / CPG-Nuke CMS installed on the remote
host suffers from multiple cross-site scripting vulnerabilities due to
its failure to sanitize user-input to several variables in various
modules.  An attacker can exploit these flaws to steal cookie-based
authentication credentials and perform other such attacks. 

Solution : Upgrade to a version of CPG Dragonfly CMS greater than
9.0.2.0 when it becomes available. 

Risk factor : Low";
  script_description(english:desc["english"]);

  script_summary(english:"Checks for multiple cross-site scripting vulnerabilities in CPG Dragonfly");

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencie("cross_site_scripting.nasl");
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


# Check various directories for CPG Dragonfly / CPG-Nuke.
foreach dir (cgi_dirs()) {
  # Try to exploit the vulnerability with our XSS.
  req = http_get(
    item:string(
      dir, "/index.php?",
      "name=Your%20Account&",
      "profile=anyone%22%3E" , exss
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if ...
  if (
    # it's from CMS Dragonfly / CPG-Nuke and...
    egrep(string:res, pattern:'META NAME="GENERATOR" CONTENT="CPG(-Nuke|Dragonfly)', icase:TRUE) &&
    # we see our exploit.
    (xss >< res)
  ) {
    security_warning(port);
    exit(0);
  }
}
