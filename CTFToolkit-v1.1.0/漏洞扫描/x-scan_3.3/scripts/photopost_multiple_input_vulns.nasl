#
# (C) Tenable Network Security
#
# 

if (description) {
  script_id(17649);
  script_version("$Revision: 1.2 $");

  script_bugtraq_id(12920);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"15096");
    script_xref(name:"OSVDB", value:"15097");
    script_xref(name:"OSVDB", value:"15098");
    script_xref(name:"OSVDB", value:"15099");
    script_xref(name:"OSVDB", value:"15100");
  }

  name["english"] = "PhotoPost Multiple Input Validation Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
The version of PhotoPost PHP installed on the remote host is prone to
multiple input validation vulnerabilities:

  o Multiple SQL Injection Vulnerabilities
    The application fails to properly sanitize user-input via
    the 'sl' parameter of the 'showmembers.php' script, and 
    the 'photo' parameter of the 'showphoto.php' script. An 
    attacker can exploit these flaws to manipulate SQL 
    queries, possibly destroying or revealing sensitive data.

  o Multiple Cross-Site Scripting Vulnerabilities
    The application fails to properly sanitize user-input via
    the 'photo' parameter of the 'slideshow.php' script, the
    'cat', 'password', 'si', 'ppuser', and 'sort' parameters
    of the 'showgallery.php' script, and the 'ppuser', 'sort', 
    and 'si' parameters of the 'showmembers.php' script.
    An attacker can exploit these flaws to inject arbitrary 
    HTML or code script in a user's browser in the context of 
    the affected web site, resulting in theft of 
    authentication data or other such attacks. 

Solution : None at this time.

Risk factor : Medium";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple input validation vulnerabilities in PhotoPost PHP";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencie("photopost_detect.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/photopost"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Try some SQL injection exploits.
  exploits = make_list(
    "/showmembers.php?sl='nessus",
    "/showphoto.php?photo='nessus"
  );
  foreach exploit (exploits) {
    req = http_get(item:string(dir, exploit), port:port);
    res = http_keepalive_send_recv(port:port, data:req);
    if (res == NULL) exit(0);

    if (
      egrep(string:res, pattern:"argument is not a valid MySQL result resource") ||
      egrep(string:res, pattern:">MySQL error reported!<.+>Script:")
    ) {
      security_warning(port);
      exit(0);
    }
  }
}


