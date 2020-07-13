#
# (C) Tenable Network Security
#
# 

if (description) {
  script_id(18083);
  script_version("$Revision: 1.2 $");

  script_cve_id("CAN-2005-1172");
  script_bugtraq_id(13218);

  name["english"] = "Coppermine Photo Gallery X-Forwarded-For Logging Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
According to its version number, the version of Coppermine Photo Gallery
installed on the remote host suffers from a cross-site scripting
vulnerability when logging user comments.  An attacker can exploit this
flaw by passing along a specially-crafted 'X-Forwarded-For' header to
steal an admin's cookie when he views the application logs or to launch
other types of cross-site scripting attacks against the affected
application. 

Solution : Upgrade to Coppermine Photo Gallery version 1.3.1 or later. 

Risk factor : Low";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for X-Forwarded-For Logging Vulnerability in Coppermine Photo Gallery";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencie("coppermine_gallery_detect.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/coppermine_photo_gallery"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  # nb: catches versions like "1.3.0-Nuke" too.
  if (ver =~ "(0|1\.([0-2]|3\.0([^0-9]|$)))") security_warning(port);
}
