#
# (C) Tenable Network Security
#
# 

if (description) {
  script_id(18101);
  script_version("$Revision: 1.1 $");

  script_bugtraq_id(13287, 13289);

  name["english"] = "Coppermine Photo Gallery FAVPICS SQL Injection Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
According to its version number, the version of Coppermine Photo Gallery
installed on the remote host suffers from multiple SQL injection
vulnerabilities due to its failure to sanitize user-supplied cookie data
before using it in SQL queries in the scripts
'include/functions.inc.php' as well as 'zipdownload.php'.  An attacker
may be able to use the first flaw to reveal sensitive data and the
second to download any file accessible to the web server userid on the
remote host, although access to 'zipdownload.php' is not enabled by
default. 

See also : http://www.waraxe.us/advisory-42.html

Solution : Upgrade to Coppermine Photo Gallery version 1.3.3 or later. 

Risk factor : Medium";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for FAVPICS SQL injection vulnerabilities in Coppermine Photo Gallery";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

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
  if (ver =~ "(0|1\.([0-2]|3\.[0-2]([^0-9]|$)))") security_warning(port);
}
