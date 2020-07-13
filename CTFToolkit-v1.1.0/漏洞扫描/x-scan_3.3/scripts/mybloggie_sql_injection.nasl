#
# Script by Noam Rathaus GPLv2
#
# Multiple vulnerabilities in myBloggie 2.1.1
# "Alberto Trivero" <trivero@jumpy.it>
# 2005-05-05 17:46

if(description)
{
 script_id(18209);
 script_bugtraq_id(13507, 13192);
 script_version("$Revision: 1.1 $");
 
 name["english"] = "myBloggie Multiple Vulnerabilities";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running myBloggie, a web log system written in PHP.

The remote version of this software has been found contain multiple 
vulnerabilities:

 * Full Path Disclosure
 Due to an improper sanitization of the post_id parameter, it's possible
 to show the full path by sending a simple request.

 * Cross-Site Scripting (XSS)
 Input passed to 'year' parameter in viewmode.php is not properly sanitised
 before being returned to users. This can be exploited execute arbitrary 
 HTML and script code in a user's browser session in context of a vulnerable 
 site.

 * SQL Injection
 When myBloggie get the value of the 'keyword' parameter and put it in the
 SQL query, don't sanitise it. So a remote user can do SQL injection attacks.

Solution: Patches have been provided by the vendor and are available at:
http://mywebland.com/forums/viewtopic.php?t=180

Risk factor: High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of a myBloggie";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2005 Noam Rathaus");
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
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);
function check(loc)
{
 req = http_get(item:string(loc, "/index.php?mode=viewid&post_id=1'"), port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly:0);
 if( r == NULL )exit(0);
 if("You have an error in your SQL syntax" >< r)
 {
  security_warning(port);
  exit(0);
 }
}


foreach dir ( cgi_dirs() )
{
 check(loc:dir);
}

