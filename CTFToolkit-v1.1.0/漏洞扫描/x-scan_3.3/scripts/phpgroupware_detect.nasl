#
# (C) Tenable Network Security
#

if(description)
{
 script_id(15982);
 script_version ("$Revision: 1.2 $");
 name["english"] = "PhpGroupWare Detection"; 

 script_name(english:name["english"]);
 
 desc["english"] = "
This check determines the presence of PHPGroupWare, a groupware system
written in  PHP, and store its location and version in the Nessus KB.

Risk factor : Low";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for PhpGroupWare";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port)) exit(0);


function check(url)
{
	req = http_get(item:string(url, "/login.php"), port:port);
	r = http_keepalive_send_recv(port:port, data:req);
	if ( r == NULL ) 
		exit(0);

    	if ("phpGroupWare http://www.phpgroupware.org" >< r)
	{
		version = egrep(pattern:".*phpGroupWare ([0-9.]+).*", string:r);
		if ( version )
		{
		 version = ereg_replace(pattern:".*phpGroupWare ([0-9.]+).*", string:version, replace:"\1");
		 if ( url == "" ) url = "/";
	 	 set_kb_item(name:"www/" + port + "/phpGroupWare", value:version + " under " + url );
    		 {
			report = "
phpGroupWare " + version + ", a groupware application written in PHP, is installed on
the remote host under " + url;
 			security_note(port:port, data:report);
		 }
		}
    	}
}

check(url:"");
check(url:"/phpgroupware/");
check(url:"/phpgw/");

foreach dir (cgi_dirs())
{
 check(url:dir);
}
