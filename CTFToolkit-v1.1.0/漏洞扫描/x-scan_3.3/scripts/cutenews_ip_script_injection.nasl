#
# (C) Tenable Network Security
#

if(description) {
  script_id(17256);
  script_version("$Revision: 1.2 $");

  script_bugtraq_id(12691);
 
  name["english"] = "CuteNews X-Forwarded-For Script Injection Vulnerability";
  script_name(english:name["english"]);

  desc["english"] = "
According to its version number, the remote host is running a version
of CuteNews that allows an attacker to inject arbitrary script through
the variables 'X-FORWARDED-FOR' or 'CLIENT-IP' when adding a comment. 
On one hand, an attacker can inject a client-side script to be executed
by an administrator's browser when he/she chooses to edit the added
comment.  On the other, an attacker with local access could leverage
this flaw to run arbitrary PHP code in the context of the web server
user. 

Solution : none at this time.
Risk factor : Medium";
  script_description(english:desc["english"]);

  summary["english"] = "Checks for X-Forwarded-For script injection vulnerability in CuteNews";
  script_summary(english:summary["english"]);

  script_category(ACT_GATHER_INFO);
  family["english"] = "CGI abuses";
  script_family(english:family["english"]);

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_require_ports("Services/www", 80);
  script_dependencies("cutenews_detect.nasl", "http_version.nasl");
  exit(0);
}


include("http_func.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0);

# Test an install.
install = get_kb_item(string("www/", port, "/cutenews"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  # 1.3.6 is known to be affected, other versions likely are.
  if (ver =~ "^(0.*|1\.([0-2].*|3|3\.[0-6]))") {
    security_warning(port);
    exit(0);
  }
}

