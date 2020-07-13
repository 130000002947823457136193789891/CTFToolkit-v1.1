#
# (C) Tenable Network Security
#
# 

if (description) {
  script_id(18245);
  script_version("$Revision: 1.3 $");

  script_bugtraq_id(13605, 13606);

  name["english"] = "Bugzilla Information Disclosure Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
According to its banner, the remote host is running a version of
Bugzilla suffers from two information disclosure vulnerabilities:

  - If a user is prompted to log in while attempting to 
    view a chart, his password will be embedded in the
    report URL and thus become visible in the web server's
    logs.

  - Users can learn whether an invisible product exists in
    Bugzilla because the application uses one error
    message if it does not and another if it does but 
    access is denied. In addition, users can enter bugs
    even when bug entry is closed provided a valid
    product name is used.

See also : http://www.bugzilla.org/security/2.16.8/
Solution : Upgrade to Bugzilla 2.18.1 or later.
Risk factor : Low";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for information disclosure vulnerabilities in Bugzilla";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencie("bugzilla_detect.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);


# Check the installed version.
ver = get_kb_item(string("www/", port, "/bugzilla/version"));
if (
  ver && 
  ver =~ "^2\.([0-9]\..*|1[0-9]$|1[0-5]\..*|16\.[0-8][^0-9]?|17\..*|18\.0|19\.[0-2][^0-9]?)"
) security_warning(port);
