#
# (C) Noam Rathaus GPLv2
#

# b2Evolution Security Flaws - SQL Injection - Forgot to incldue a solution.
# From: r0ut3r <shady.underground@gmail.com>
# Date: 2005-01-06 10:05

if(description)
{
 script_id(16121);
 script_version("$Revision: 1.1 $");
 script_bugtraq_id(12179);
 
 name["english"] = "b2Evolution title SQL Injection";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running b2evolution, a blog engine written in PHP.

There is an SQL injection vulnerability in the remote version of this software
which may allow an attacker to execute arbitrary SQL statements against the
remote database by providing a malformed value to the 'title' argument
of index.php.

Solution : None at this time
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of an SQL injection in title parameter";
 
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
if(!can_host_php(port:port))exit(0);

function check(loc)
{
 req = http_get(item:string(loc, "/index.php?blog=1&title='&more=1&c=1&tb=1&pb=1"), port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly: 1);
 if( r == NULL )exit(0);

 if("SELECT DISTINCT ID, post_author, post_issue_date" >< r)
 {
 	security_hole(port);
	exit(0);
 }
}

foreach dir ( cgi_dirs() )
{
 check(loc:dir);
}

