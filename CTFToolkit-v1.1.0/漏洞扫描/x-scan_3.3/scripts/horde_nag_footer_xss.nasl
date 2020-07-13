#
# (C) Tenable Network Security
#
# 

if (description) {
  script_id(18136);
  script_version("$Revision: 1.1 $");

  script_bugtraq_id(13363);

  name["english"] = "Nag common-footer.inc Cross-Site Scripting Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
According to its version, the remote installation of Nag fails to
fully sanitize user-supplied input when setting the parent frame's
page title by javascript in 'templates/common-footer.inc'.  By
leveraging this flaw, an attacker may be able to inject arbitrary HTML
and script code into a user's browser to be executed in the context of
the affected web site, thereby resulting in the theft of session
cookies and similar attacks. 

Solution : Upgrade to Nag 1.1.3 or later.

Risk factor : Medium";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for cross-site scripting vulnerability in Nag common-footer.inc";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencie("horde_nag_detect.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/horde_nag"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];
  if (ver =~ "^(0|1\.(0|1$|1\.[0-2]([^0-9]|$)))") security_warning(port);
}
