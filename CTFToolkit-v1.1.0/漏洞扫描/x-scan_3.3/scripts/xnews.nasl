#
# This script was written by Audun Larsen <larsen@xqus.com>
#

if(description)
{
 script_version ("$Revision: 1.5 $");
 script_id(12068);
 script_cve_id("CAN-2002-1656");
 script_bugtraq_id(4283);
 name["english"] = "x-news 1";
 name["francais"] = "x-news 1";
 script_name(english:name["english"], francais:name["francais"]);

 desc["english"] = "
X-News is a news management system, written in PHP.  X-News uses a
flat-file database to store information.  It will run on most Unix and
Linux variants, as well as Microsoft Windows operating systems. 

X-News stores user IDs and MD5 hashes in a world-readable file
(db/users.txt).  This is the same information that is issued by X-News
in cookie-based authentication credentials.  An attacker may
incorporate this information into cookies and then submit them to gain
unauthorized access to the X-News administrative account. 

Solution : Deny access to the files inside the db/ directory through
           the webserver. 
Risk factor : Low";

 script_description(english:desc["english"]);
 summary["english"] = "Check if version of x-news 1.x is installed";
 script_summary(english:summary["english"]);
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004 Audun Larsen");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_require_ports("Services/www", 80);
 script_dependencies("http_version.nasl");
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);


foreach z (cgi_dirs())
{
 req = http_get(item:string(z, "/x_news.php"), port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if( res == NULL ) exit(0);
 if("Powered by <a href='http://www.xqus.com'>x-news</a> v.1.1" >< res)
 {
   req2 = http_get(item:string(z, "/db/users.txt"), port:port);
   res2 = http_keepalive_send_recv(port:port, data:req2);
   if( res2 == NULL ) exit(0);
   if("|1" >< res2)
   {
      security_warning(port);
      exit(0);
   } 
  } 
}
