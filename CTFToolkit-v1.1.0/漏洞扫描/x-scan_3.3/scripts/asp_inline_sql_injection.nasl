#
# (C) Noam Rathaus GPLv2
#

# ASP Inline Corporate Calendar SQL injection
# "Zinho" <zinho@hackerscenter.com>
# 2005-05-03 18:50

if(description)
{
 script_id(18187);
 script_bugtraq_id(13487, 13485);
 script_version("$Revision: 1.2 $");
 
 name["english"] = "ASP Inline Corporate Calendar SQL injection";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running Corporate Calendar, an ASP script to manage a 
calendar shared by users. It has been downloaded by thousands people, and 
it is considered one of the most successful ASP script at hotscripts.com.

Multiple SQL injections affect ASP Inline Corporate Calendar.

Solution : Disable this script
Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of an SQL injection in defer.asp";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2005 Noam Rathaus");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "httpver.nasl", "http_version.nasl");
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

function check(loc)
{
 req = http_get(item:string(loc, "/calendar/details.asp?Event_ID='"), port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly: 1);
 if( r == NULL )exit(0);
 if("Syntax error in string in query expression 'Event_ID LIKE" >< r)
 {
  security_hole(port);
  exit(0);
 }
}

check(loc:"");

foreach dir (make_list(cgi_dirs()))
{
 check(loc:dir);
}

