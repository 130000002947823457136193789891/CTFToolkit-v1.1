#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# This script is released under the GNU GPLv2
#

if(description)
{
 script_id(18628);
 script_bugtraq_id(14099);
 script_version ("$Revision: 1.1 $");
 name["english"] = "YaPig password protected directory access flaw";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host seems to be running YaPiG, an Image Gallery script written in PHP.

The remote version of this software contains a flaw that can let a malicious user 
view images in password protected directories.

Successful exploitation of this issue may allow an attacker to access unauthorized 
images on a vulnerable server.

Solution : Update to newer or disable this CGI suite
Risk factor : Low";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for YaPiG version";
 
 script_summary(english:summary["english"]);
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2005 David Maciejak");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

port = get_http_port(default:80);
if(!get_port_state(port)) exit(0);


function check(url)
{
	req = http_get(item:string(url, "/index.php"), port:port);
	r = http_keepalive_send_recv(port:port, data:req);
	if ( r == NULL ) exit(0);
	#Powered by <a href="http://yapig.sourceforge.net" title="Yet Another PHP Image Gallery">YaPig</a> V0.92b
 	if(egrep(pattern:"Powered by .*YaPig.* V0\.([0-8][0-9][^0-9]|9[0-3]|94[a-u])", string:r))
 	{
 		security_note(port);
		exit(0);
	}
 
}

if ( thorough_tests )
{
 check(url:"/yapig/");
 check(url:"/yapig-0.92b/");
 check(url:"/yapig-0.93u/");
 check(url:"/yapig-0.94u/");
 check(url:"/gallery/");
 check(url:"/photos");
 check(url:"/photo");
}

foreach dir (cgi_dirs())
{
 check(url:dir);
}
