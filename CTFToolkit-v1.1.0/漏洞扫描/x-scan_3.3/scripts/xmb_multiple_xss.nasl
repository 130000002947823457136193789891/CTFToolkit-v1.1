#
# (C) Tenable Network Security
#


if (description) {
  script_id(17608);
  script_version("$Revision: 1.2 $");

  script_cve_id("CAN-2005-0885");
  script_bugtraq_id(12886);

  script_name(english:"XMB Forum Multiple Cross-Site Scripting Vulnerabilities");
  desc["english"] = "
The remote host is running XMB Forum, a web forum written in PHP.

According to its banner, the version of XMB installed on the remote
host suffers from multiple cross-site scripting vulnerabilities.  A
remote attacker can exploit these flaws by passing arbitrary script
code through the 'Mood' parameter in various scripts or through the
'Send To' field of the U2U feature will to be rendered in a browser in
the context of the affected web site.

Solution : Upgrade to XMB 1.9.2 or greater when it becomes available. 
Risk factor : Low";
  script_description(english:desc["english"]);

  script_summary(english:"Checks for multiple cross-site scripting vulnerabilities in XMB Forum");

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencie("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Check various directories for XMB.
foreach dir (cgi_dirs()) {
  # Look for the version number in the login script.
  req = http_get(item:string(dir, "/misc.php?action=login"), port:port);
  res = http_keepalive_send_recv(port:port, data:req);

  # To actually exploit the vulnerabilities reliably, you need
  # to be logged in so the best we can do is a banner check.
  if (
    res &&
    # Sample banners:
    #   Powered by <b><a href="http://www.xmbforum.com">XMB</a></b> v1.05</font><br />
    #   Powered by <b><a href="http://www.xmbforum.com">XMB</a></b> v1.5 RC4: Summer Forest<br />
    #   Powered by <a href="http://www.xmbforum.com" target="blank">XMB</a> 1.6 Magic Lantern Final<br></b>
    #   Powered by <a href="http://www.xmbforum.com" target="blank">XMB</a> 1.6 v2b Magic Lantern Final<br></b>
    #   Powered by XMB 1.8 Partagium SP1<br />
    #   Powered by XMB 1.9 Nexus (beta)<br />
    #   Powered by XMB 1.9.1 RC1 Nexus<br />
    #   Powered by XMB 1.9.2 Nexus (pre-Alpha)<br />
    egrep(string:res, pattern:"Powered by .*XMB(<[^>]+>)* v?(0.*|1\.([0-8].*|9(\.[01])?)) ", icase:TRUE)
  ) {
    security_warning(port);
    exit(0);
  }
}
