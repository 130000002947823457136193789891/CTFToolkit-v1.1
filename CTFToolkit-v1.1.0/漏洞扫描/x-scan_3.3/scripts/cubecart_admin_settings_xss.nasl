#
# (C) Tenable Network Security
#


if (description) {
  script_id(17260);
  script_version("$Revision: 1.3 $");

  script_cve_id("CAN-2005-0606", "CAN-2005-0607");
  script_bugtraq_id(12658);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"13810");
    script_xref(name:"OSVDB", value:"14213");
    script_xref(name:"OSVDB", value:"14214");
    script_xref(name:"OSVDB", value:"14215");
    script_xref(name:"OSVDB", value:"14216");
    script_xref(name:"OSVDB", value:"14217");
    script_xref(name:"OSVDB", value:"14218");
    script_xref(name:"OSVDB", value:"14219");
    script_xref(name:"OSVDB", value:"14220");
    script_xref(name:"OSVDB", value:"14221");
  }

  name["english"] = "CubeCart settings.inc.php Cross-Site Scripting and Path Disclosure Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
According to its banner, this version of CubeCart installed on the
remote host suffers from multiple cross-site scripting and path
disclosure vulnerabilities due to a failure to sanitize user input in
'admin/settings.inc.php'. 

See also : http://lostmon.blogspot.com/2005/02/cubecart-20x-multiple-variable-xss.html

Solution : Upgrade to CubeCart 2.0.6 or later.
Risk factor : Medium";
  script_description(english:desc["english"]);
 
  summary["english"] = "Detects cross-site scripting and path disclosure vulnerabilities in CubeCart's settings.inc.php";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");
 
  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencie("cubecart_detect.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("http_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/cubecart"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  # If it's CubeCart 2.0.0 - 2.0.5, there's a problem.
  if (ver =~ "2\.0\.[0-5]") security_warning(port);
}
