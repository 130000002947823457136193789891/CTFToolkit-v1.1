#
# (C) Tenable Network Security
#
# 

  desc["english"] = "
The version of ArGoSoft Mail Server Pro installed on the remote host
suffers from several vulnerabilities, including :

  - Unauthenticated Account Creation Vulnerability
    The application does not authenticate requests sent through
    the web interface before creating mail accounts and may
    create them even if ArGoSoft has been configured not to.

  - Multiple Cross-Site Scripting Vulnerabilities
    ArGoSoft fails to filter some HTML tags in email messages;
    eg, the SRC parameter in an IMG tag. An attacker may be
    able to run arbitrary HTML and script code in a user's 
    browser within the context of the affected web site if 
    the user reads email using ArGoSoft's web interface.

See also : http://www.securityfocus.com/archive/1/396694

Solution : Upgrade to ArGoSoft Mail Server Pro 1.8.7.7 or newer when
they become available. 

Risk factor : High";


if (description) {
  script_id(18140);
  script_version("$Revision: 1.1 $");

  script_bugtraq_id(13323, 13326);

  name["english"] = "Multiple Vulnerabilities in ArGoSoft Mail Server Pro <= 1.8.7.6";
  script_name(english:name["english"]);
 
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple vulnerabilities in ArGoSoft Mail Server Pro <= 1.8.7.6";
  script_summary(english:summary["english"]);
 
  script_category(ACT_MIXED_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencie("find_service.nes", "http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


# Make sure the server's banner indicates it's from ArGoSoft Mail Server.
port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
banner = get_http_banner(port:port);
if (!banner || banner !~ "^Server: ArGoSoft Mail Server") exit(0);


# Check for the vulnerability.
#
# - if safe checks are enabled...
if (safe_checks()) {
  # Test the version number.
  if (banner =~ "^Server: ArGoSoft .+ \((0|1\.([0-7]|8\.([0-6]|7\.[0-6])))") {
    desc = str_replace(
      string:desc["english"],
      find:"Solution :",
      replace:string(
        "***** Nessus has determined the vulnerability exists on the remote\n",
        "***** host simply by looking at the version number of ArGoSoft\n",
        "***** installed there.\n",
        "\n",
        "Solution :"
      )
    );
    security_hole(port:port, data:desc);
  }
}
# - otherwise, try to create an account
else {
  # Specify a user / password to create. gettimeofday() serves
  # to avoid conflicts and have a (somewhat) random password.
  now = split(gettimeofday(), sep:".", keep:0);
  user = string("nessus", now[0]);
  pass = now[1];

  postdata = string("username=", user, "&password=", pass, "&password1=", pass, "&submit=Add");
  req = string(
    "POST /addnew HTTP/1.1\r\n",
    "Host: ", get_host_name(), "\r\n",
    "Content-Type: application/x-www-form-urlencoded\r\n",
    "Content-Length: ", strlen(postdata), "\r\n",
    "\r\n",
    postdata
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res && egrep(string:res, pattern:"User has been successfully added.", icase:TRUE)) {
    desc = str_replace(
      string:desc["english"],
      find:"Solution :",
      replace:string(
        "**** Nessus has successfully exploited this vulnerability by adding the\n",
        "**** user ", user, " to ArGoSoft on the remote host; you may wish\n",
        "**** to remove it at your convenience.\n",
        "\n",
        "Solution :"
      )
    );
    security_hole(port:port, data:desc);
  }
}
