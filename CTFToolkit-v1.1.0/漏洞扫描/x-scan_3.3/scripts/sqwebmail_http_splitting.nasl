#
# (C) Tenable Network Security
#
# 

if (description) {
  script_id(18372);
  script_version("$Revision: 1.1 $");

  script_cve_id("CAN-2005-1308");
  script_bugtraq_id(13374);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"15819");
  }

  name["english"] = "SqWebMail HTTP Response Splitting Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
The remote host is running a version of SqWebMail that does not
properly sanitize user-supplied input through the 'redirect'
parameter.  An attacker can exploit this flaw to inject arbitrary HTML
and script code into a user's browser to be executed within the
context of the affected web site.  Such attacks could lead to session
cookie and password theft for users who read mail with SqWebMail. 

See also : http://www.hackerscenter.com/archive/view.asp?id=2300
Solution : Unknown at this time.
Risk factor: Low";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for HTTP response splitting vulnerability in SqWebMail";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
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


# For each CGI directory...
installs = 0;
foreach dir (cgi_dirs()) {
  # Try to exploit the flaw.
  req = http_get(
    item:string(
      dir, "/sqwebmail?",
      "redirect=%0d%0a%0d%0a", SCRIPT_NAME
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req);
  if (res == NULL) exit(0);

  # There's a problem if there's a redirect.
  if (
    egrep(string:res, pattern:'^Refresh: 0; URL="$', icase:TRUE) &&
    egrep(string:res, pattern:string("^", SCRIPT_NAME, "$"), icase:TRUE)
  ) {
    security_note(port);
    exit(0);
  }
}
