#
# This script was written by Noam Rathaus
#
# GPLv2
#

if(description)
{
  script_id(12648);
  script_version("$Revision: 1.3 $");
  name["english"] = "SQL Disclosure in Invision Power Board";
  script_name(english:name["english"]);
 
  desc["english"] = "
There is a vulnerability in the current version of Invision Power Board
that allows an attacker to reveal the SQL queries used by the product, and
any page that was built by the administrator using the IPB's interface,
simply by appending the variable 'debug' to the request.

Solution : Upgrade to the newest version of this software.
Risk factor : High";

  script_description(english:desc["english"]);
 
  summary["english"] = "Detect IPB SQL Disclosure";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
 
  script_copyright(english:"This script is Copyright (C) 2004 Noam Rathaus");

  family["english"] = "CGI abuses";
  script_family(english:family["english"]);
  script_dependencie("invision_power_board_detect.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if (! port) exit(0);

# Test an install.
install = get_kb_item(string("www/", port, "/invision_power_board"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
 path = matches[2];

 req = http_get(item:string(path, "/"), port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);

 find = string("Powered by Invision Power Board");
 if ( find >< res )
 {
  req = http_get(item:string(path, "/?debug=whatever"), port:port);
  res = http_keepalive_send_recv(port:port, data:req);
  if ( res == NULL ) exit(0);

  find = string("SQL Debugger");
  find2 = string("Total SQL Time");
  find3 = string("mySQL time");

  if (find >< res || find2 ><  res || find3 >< res )
	{
	 security_hole(port);
	 exit(0);
	}
 }
}

