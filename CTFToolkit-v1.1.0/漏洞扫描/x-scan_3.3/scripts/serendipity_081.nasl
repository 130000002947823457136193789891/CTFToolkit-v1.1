#
# (C) Tenable Network Security
#
# 

if (description) {
  script_id(18298);
  script_version("$Revision: 1.1 $");
  script_bugtraq_id(13669);

  name["english"] = "Serendipity < 0.8.1 Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
According to its banner, the version of Serendipity installed on the
remote host suffers from multiple vulnerabilities:

  - Unauthorized File Upload Vulnerability
    There is a possible flaw that may allow editors to upload 
    arbitrary media files when they otherwise would not be
    allowed to do so.

  - Multiple Cross-Site Scripting Vulnerabilities
    The 'templedropdown' and 'shutbox' plugins may allow
    attackers to inject arbitrary HTML and script code into
    users' browsers, thereby facilitating cross-site
    scriptings attacks.

See also : http://sourceforge.net/project/shownotes.php?release_id=328092
Solution : Upgrade to Serendipity version 0.8.1 or later. 
Risk factor : Medium";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple vulnerabilities in Serendipity < 0.8.1";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencie("serendipity_detect.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/serendipity"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  # nb: version 0.8.1 fixes the flaw.
  if (ver =~ "0\.([0-7]|8([^0-9.]|$))") security_warning(port);
}
