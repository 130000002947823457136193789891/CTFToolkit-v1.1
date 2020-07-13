#
# This script was written by Noam Rathaus
#
# GPLv2
#
# From: loofus@0x90.org - loofus
# Subject: Pivot Remote Code Execution Vulnerability
# Date: 2004-06-17
#
# changes by rd: description and detection method
#

if(description)
{
  script_id(12282);
  name["english"] = "File Inclusion Vulnerability in Pivot";
  script_version("$Revision: 1.2 $");
  script_name(english:name["english"]);
 
  desc["english"] = "
Pivot is a set of PHP scripts designed to maintain dynamic web pages.

There is a flaw in the file module_db.php which may let an attacker execute
arbitrary commands on the remote host by forcing the remote Pivot installation
to include a PHP file hosted on an arbitrary third-party website.

Solution : Upgrade to Pivot 1.14.1 or disable this CGI altogether
Risk factor : High";

  script_description(english:desc["english"]);
 
  summary["english"] = "Detect Pivot File Inclusion Vulnerability";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2004 Noam Rathaus");

  family["english"] = "CGI abuses";
  script_family(english:family["english"]);
  script_dependencie("http_version.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if (! get_port_state(port) ) exit(0);
if (! can_host_php(port:port) ) exit(0);

function check_dir(path)
{
 req = http_get(item:string(path, "/modules/module_db.php?pivot_path=http://xxxxxxxxxx/"), port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);
 if ( "http://xxxxxxxxxx/modules/module_db_xml.php" >< res )
 {
  security_hole(port);
  exit(0);
 }
}

foreach dir (make_list("/pivot/", cgi_dirs())) check_dir(path:dir);
