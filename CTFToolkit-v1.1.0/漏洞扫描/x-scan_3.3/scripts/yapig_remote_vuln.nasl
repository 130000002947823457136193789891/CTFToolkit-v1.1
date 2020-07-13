#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
#  (C) Tenable Network Security
#
#  Ref: aCiDBiTS <acidbits@hotmail.com>
# This script is released under the GNU GPLv2


if(description)
{
 script_id(14269);
 script_bugtraq_id(10891);
 script_version ("$Revision: 1.6 $");
 name["english"] = "YaPiG remote server-side script execution vulnerability";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host seems to be running YaPiG, a PHP Image Gallery script.

This version may allow a remote attacker to execute malicious scripts 
on a vulnerable system. 
This issue exists due to a lack of sanitization of user-supplied data.

It is reported that an attacker may be able to upload content that will 
be saved on the server with a '.php' extension. 
When this file is requested by the attacker, the contents of the file 
will be parsed and executed by the PHP engine, rather than being sent.

Successful exploitation of this issue may allow an attacker to execute 
malicious script code on a vulnerable server. 

Solution : Update to newer or disable this CGI suite

Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for YaPiG version";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
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

if(!get_port_state(port))
	exit(0);

if(http_is_dead(port:port))
	exit(0);

function check(url)
{
	req = http_get(item:string(url, "index.php"), port:port);
	r = http_keepalive_send_recv(port:port, data:req);
	if ( r == NULL ) 
		exit(0);
#Powered by <a href="http://yapig.sourceforge.net" title="Yet Another PHP Image Gallery">YaPig</a> V0.92b
 	if(egrep(pattern:"Powered by .*YaPig.* V0.92b", string:r))
 	{
 		security_warning(port);
		exit(0);
	}
 
}

check(url:"/");
check(url:"/yapig/");
check(url:"/yapig-0.92b/");
check(url:"/gallery/");
check(url:"/photos");
check(url:"/photo");

foreach dir (cgi_dirs())
{
 check(url:dir);
}
