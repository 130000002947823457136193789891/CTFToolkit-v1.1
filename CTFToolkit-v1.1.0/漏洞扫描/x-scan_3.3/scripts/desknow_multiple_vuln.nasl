#
# (C) Noam Rathaus GPLv2
#
# chewkeong@security.org.sg
# 2005-02-03 00:34
# DeskNow Mail and Collaboration Server Directory Traversal Vulnerabilities

if(description)
{
 script_id(16308);
 script_cve_id("CAN-2005-0332");
 script_bugtraq_id(12421);
 script_version("$Revision: 1.2 $");
 
 name["english"] = "DeskNow Mail and Collaboration Server Directory Traversal Vulnerabilities";

 script_name(english:name["english"]);
 
 desc["english"] = "
DeskNow Mail and Collaboration Server is a full-featured and integrated 
mail and instant messaging server, with webmail, secure instant 
messaging, document repository, shared calendars, address books, 
message boards, web-publishing, anti-spam features, Palm and 
PocketPC access and much more.

A directory traversal vulnerability was found in DeskNow webmail 
file attachment upload feature that may be exploited to upload 
files to arbitrary locations on the server. A malicious webmail 
user may upload a JSP file to the script directory of the server, 
and executing it by requesting the URL of the upload JSP file. 
A second directory traversal vulnerability exists in the document 
repository file delete feature. This vulnerability may be exploited 
to delete arbitrary files on the server.

Solution : Upgrade to DeskNow version 2.5.14 or newer
Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of an old version of DeskNow";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Noam Rathaus");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 8080);
 exit(0);
}

#
# The script code starts here
#


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:8080);

if(!get_port_state(port))exit(0);

function check(loc)
{
 req = http_get(item:string(loc, "/index.html"), port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly: 1);
 if( r == NULL )exit(0);

 if ( egrep(pattern:"DeskNow&reg; (0\.|1\.|2\.[0-4]\.|2\.5\.[0-9][^0-9]|2\.5\.1[0-3])", string:r) ) 
 { 
  security_warning(port);
  exit(0);
 }
}

foreach dir (make_list("/desknow", cgi_dirs()))
{
 check(loc:dir);
}

