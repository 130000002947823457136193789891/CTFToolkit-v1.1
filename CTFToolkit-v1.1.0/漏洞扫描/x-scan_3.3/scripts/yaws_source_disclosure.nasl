#
# (C) Tenable Network Security
#

if(description)
{
 script_id(18522);
 script_bugtraq_id(13981);
 script_version ("$Revision: 1.1 $");
 name["english"] = "Yaws Remote Source Code Disclosure Vulnerability";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running the YAWS web server. 

The remote version of this software is vulnerable to a source code disclosure
issue. By requesting a .yaws script following by %00, an attacker may force
the remote server to disclose its source code.

Since scripts may contain sensitive information such as login and passwords,
an attacker may exploit this flaw to obtain some credentials on the remote
host or a better understanding of the security of the .yaws CGIs.

Solution :  Upgrade to YAWS 1.56 or newer
Risk factor : High";
	

 script_description(english:desc["english"]);
 
 summary["english"] = "downloads the source of .yaws scripts";
 script_summary(english:summary["english"]);
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "webmirror.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");

function check(file)
{
  req = http_get(item:string(file, "%00"), port:port);
  r = http_keepalive_send_recv(port:port, data:req);
  if  ( ! r ) exit(0);
  if("<erl>" >< r && "</erl>" >< r )
	{
  	security_hole(port);
	return(1);
	}
 return(0);
}


port = get_http_port(default:80);
banner = get_http_banner(port:port);
if ( "Server: Yaws/" >!< banner ) exit(0);

files = get_kb_list(string("www/", port, "/content/extensions/yaws"));
if(isnull(files))exit(0);
files = make_list(files);
check(file:files[0]); 
