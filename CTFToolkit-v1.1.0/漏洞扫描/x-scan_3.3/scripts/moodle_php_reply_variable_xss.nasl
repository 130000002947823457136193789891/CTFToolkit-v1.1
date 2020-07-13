#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
#  (C) Tenable Network Security
#
#  Ref: Javier Ubilla and Ariel
#
# This script is released under the GNU GPLv2

if (description)
{
 script_id(14257);
 script_cve_id("CAN-2004-1711");
 script_bugtraq_id(10884);
 if ( defined_func("script_xref") ) 
	script_xref(name:"OSVDB", value:"8383");
 
 script_version("$Revision: 1.5 $");

 script_name(english:"Moodle post.php XSS");
 desc["english"] = "
The remote host is running the Moodle PHP suite.

Moodle contains a flaw that allows a remote cross site scripting attack. 
This flaw exists because the application does not validate the 'reply' 
variable upon submission to the 'post.php' script. 

This could allow a user to create a specially crafted URL that would execute
arbitrary code in a user's browser within the trust relationship between the 
browser and the server, leading to a loss of integrity.

Solution : Upgrade to Moodle 1.4 or newer.

Risk factor : Medium";

 script_description(english:desc["english"]);
 script_summary(english:"Determines if Moodle is vulnerable to post.php XSS");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses : XSS", francais:"Abus de CGI");
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);

if(!get_port_state(port))
	exit(0);
if(!can_host_php(port:port))
	exit(0);

foreach dir ( cgi_dirs() )
{
 	req = http_get(item:string(dir, "/post.php?reply=<script>document.write('Nessus plugin to detect post.php flaw');</script>"), port:port);
 	res = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 	if(res == NULL ) 
		exit(0);
 
 	if (ereg(pattern:"Nessus plugin to detect post.php flaw", string:res ))
 	{
    		security_warning(port);
		exit(0);
 	}
}


