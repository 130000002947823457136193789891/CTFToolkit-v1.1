#
# (C) Tenable Network Security



if(description)
{
 script_id(14325);
 script_bugtraq_id(10982);
 script_version ("$Revision: 1.1 $");
 
 name["english"] = "Zixforum database disclosure";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote server is running ZixForum, a set of .asp scripts to 
a web-based forum/

This program uses a database named 'ZixForum.mdb' which can be downloaded
by any client. This database contains the whole discussions, the account
information and so on.

Solution : Prevent the download of .mdb files from the remote website.
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for ZixForum.mdb";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);


if(!get_port_state(port))exit(0);


foreach d ( make_list(cgi_dirs(), "/forum") )
{
 req = http_get(item:string(d, "/news.mdb"), port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 
 if ( res == NULL ) exit(0);
 
 if("Standard Jet DB" >< res)
	{
 	 security_warning(port);
	 exit(0);
	 }
}
