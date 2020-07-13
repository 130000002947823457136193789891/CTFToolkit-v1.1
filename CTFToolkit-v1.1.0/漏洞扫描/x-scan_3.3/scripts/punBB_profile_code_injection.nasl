#
# (C) Tenable Network Security
#
# 


if (description) {
  script_id(17363);
  script_version("$Revision: 1.1 $");
  script_bugtraq_id(12828);

  name["english"] = "PunBB profile.php Input Validation Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
The version of PunBB installed on the remote host fails to properly
sanitize user input to the script 'profile.php' through the 'email'
and 'Jabber' parameters.  An attacker could exploit this flaw to embed
malicious script or HTML code in his profile.  Then, whenever someone
browses that profile, the code would be executed in that person's
browser in the context of the web site, enabling the attacker to
conduct cross-site scripting attacks. 

Solution : Upgrade to a version of PunBB greater than 1.2.3 when available
Risk factor : Low";
  script_description(english:desc["english"]);
 
  summary["english"] = "Detects input validation vulnerabilities in PunBB's profile.php";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");
 
  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencie("punBB_detect.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/punBB"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  if (ver =~ "^1\.(1|2$|2\.[1-3]([^0-9]|$))") security_warning(port);
}
