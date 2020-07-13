#
# (C) Noam Rathaus
#
# Ref: 
# From: J [jay@j-security.co.uk]
# To: full-disclosure@lists.netsys.com
# Subject: Snif 1.2.4 file retrieval bug
# Date: Thursday 27/11/2003 01:02
#


if(description)
{
 script_id(11944);
 script_version ("$Revision: 1.5 $");
 name["english"] = "Snif File Disclosure";

 script_name(english:name["english"]);
 
 desc["english"] = "
It is possible to make the remote host return the content of any world 
readable file by requesting a path outside the bound HTML root directory 
from the Snif program.

An attacker may use this flaw to view sensitive files that reside on the 
remote host.

Solution : Upgrade to Snif version 1.2.5 or newer
Risk factor : Medium";



 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the version of Snif";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Noam Rathaus");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
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
if(!can_host_php(port:port))exit(0);

foreach dir ( cgi_dirs() )
{
 req = http_get(item:dir + "/index.php", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);

 if (egrep(pattern:"snif (1\.[0-1]|1\.1a|1\.2|1\.2\.[1-4])  &copy; 2003 Kai Blankenhorn", string:res)) { security_warning(port); exit(0); }
}
