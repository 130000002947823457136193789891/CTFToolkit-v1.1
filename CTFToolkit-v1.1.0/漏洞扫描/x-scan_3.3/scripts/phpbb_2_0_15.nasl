#
# (C) Tenable Network Security
#
# 

if (description) {
  script_id(18589);
  script_version("$Revision: 1.1 $");
  script_bugtraq_id(14086);

  name["english"] = "phpBB <= 2.0.15 Remote Code Execution Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
According to its banner, the remote host is running a version of phpBB
that allows attackers to inject arbitrary PHP code to the
'viewtopic.php' script to be executed within the context of the web
server userid. 

See also : http://www.securityfocus.com/archive/1/403631/30/0/threaded
Solution : Upgrade to phpBB version 2.0.16 or later.
Risk factor : High";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for remote code execution vulnerability in phpBB <= 2.0.15";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  family["english"] = "CGI abuses";
  script_family(english:family["english"]);

  script_dependencie("phpbb_detect.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/phpBB"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];
  if (ver =~ "^([01]\..*|2\.0\.([0-9]|1[0-5])([^0-9]|$))") security_hole(port);
}
