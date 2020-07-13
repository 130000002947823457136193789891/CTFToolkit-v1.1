#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# This script is released under the GNU GPLv2
#

if(description)
{
 script_id(18523);
 script_bugtraq_id(13871, 13874, 13875, 13876, 13877);
 script_version ("$Revision: 1.1 $");
 name["english"] = "YaPiG multiple flaws";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host seems to be running YaPiG, a PHP Image Gallery script.

This version is vulenrable to multiple flaws:
-directory traversal flaw threw upload.php
-cross-site scripting and HTML injection flaws threw view.php
-remote and local file include 

Successful exploitation of this issue may allow an attacker to execute 
malicious script code on a vulnerable server.

Solution : Update to newer or disable this CGI suite

Risk factor : Medium";

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
include('global_settings.inc');

port = get_http_port(default:80);

if(!get_port_state(port))
	exit(0);

if(http_is_dead(port:port))
	exit(0);

function check(url)
{
	req = http_get(item:string(url, "/index.php"), port:port);
	r = http_keepalive_send_recv(port:port, data:req);
	if ( r == NULL ) 
		exit(0);
	#Powered by <a href="http://yapig.sourceforge.net" title="Yet Another PHP Image Gallery">YaPig</a> V0.92b
 	if(egrep(pattern:"Powered by .*YaPig.* V0\.([0-7]|9[2-3][a-z]|94[a-u])", string:r))
 	{
 		security_warning(port);
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
