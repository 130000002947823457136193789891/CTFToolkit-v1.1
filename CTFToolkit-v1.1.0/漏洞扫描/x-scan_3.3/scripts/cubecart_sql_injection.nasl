#
# (C) Tenable Network Security
#


if(description)
{
 script_id(15442);
 script_version("$Revision: 1.3 $");

 script_cve_id("CAN-2004-1580");
 script_bugtraq_id(11337);

 name["english"] = "CubeCart SQL injection";
 script_name(english:name["english"]);
 
 desc["english"] = "
There is a SQL injection issue in the remote version of CubeCart which
may allow an attacker to execute arbitrary SQL statements on the remote
host and to potentially overwrite arbitrary files on the remote system,
by sending a malformed value to the 'cat_id' argument of the file
'index.php'. 

Solution : Upgrade to the latest version of this software.
Risk factor : High";
 script_description(english:desc["english"]);
 
 summary["english"] = "SQL Injection in CubeCart";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2005 Tenable Network Security");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("cubecart_detect.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if ( ! can_host_php(port:port) ) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/cubecart"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
 loc = matches[2];

 res = http_keepalive_send_recv(port:port, data:http_get(item:loc + "/index.php?cat_id=42'", port:port));
 if ("mysql_fetch_array()" >< res) security_hole(port);
}
