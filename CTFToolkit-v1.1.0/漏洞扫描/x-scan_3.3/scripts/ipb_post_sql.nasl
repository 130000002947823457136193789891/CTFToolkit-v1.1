#
# (C) Tenable Network Security
#
#

if(description)
{
  script_id(15778);
  script_cve_id("CAN-2004-1531");
  script_bugtraq_id(11703);
  script_version("$Revision: 1.3 $");
  name["english"] = "Invision Power Board Post SQL Injection Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
The version of Invision Power Board on the remote host suffers from a
flaw that allows unauthorized users to inject SQL commands in the
remote SQL database.  An attacker may use this flaw to gain control of
the remote database and possibly to overwrite files on the remote
host. 

Solution : Upgrade to the latest version of this software.
Risk factor : High";

  script_description(english:desc["english"]);
 
  summary["english"] = "Detect Invision Power Board Post SQL Injection";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
 
  script_copyright(english:"This script is Copyright (C) 2004-2005 Tenable Network Security");

  family["english"] = "CGI abuses";
  script_family(english:family["english"]);
  script_dependencie("invision_power_board_detect.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);



# Test an install.
install = get_kb_item(string("www/", port, "/invision_power_board"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
 path = matches[2];

 req = http_get(item:string(path, "/index.php?act=Post&CODE=02&f=3&t=10&qpid=1'"), port:port);
 res = http_keepalive_send_recv(port:port, data:req);

 if ("mySQL query error: select p.*,t.forum_id FROM ibf_posts p LEFT JOIN ibf_topics t ON (t.tid=p.topic_id)" >< res)
  security_hole(port);
}
