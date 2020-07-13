#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
#  Ref: Moodle Team
#
#  This script is released under the GNU GPL v2
#

if (description)
{
 script_id(15639);
 script_bugtraq_id(11608, 11691, 12120);
 script_version("$Revision: 1.3 $");

 script_name(english:"Moodle SQL injection flaws");
 desc["english"] = "
The remote host is running a version of the Moodle suite, an open-source
course management system written in PHP, which is older than version 1.4.3.

The remote version of this software is vulnerable to SQL injection issue 
in 'glossary' module due to a lack of user input sanitization.

Solution : Upgrade to Moodle 1.4.3
Risk factor : High";

 script_description(english:desc["english"]);
 script_summary(english:"Determines if Moodle is older than 1.4.2");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses", francais:"Abus de CGI");
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

req = http_get(item:"/index.php", port:port);
res = http_keepalive_send_recv(port:port, data:req);
if(res == NULL ) exit(0);
 
if ( "Moodle - A Free, Open Source Course Management System for Online Learning</title>" >< res && 
    (egrep(pattern:"<a title=.moodle (0\..*|1\.([0-4][^0-9]|[0-4]\.[012][^0-9]))", string:res)))
{
	security_hole(port);
	exit(0);
}
