#
# (C) Noam Rathaus
#
# This script is released under the GPLv2
#

if(description)
{
 script_id(15751);
 script_version("$Revision: 1.1 $");
 script_bugtraq_id ( 10153 );
 
 name["english"] = "phpBugTracker bug.php SQL Injection";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using phpBugTracker, a PHP based bug tracking engine.

There is a bug in the remote version of this software which makes it 
vulnerable to an SQL injection vulnerability. An attacker may exploit 
this flaw to execute arbitrary SQL statements against the remote database.

Solution : Upgrade to the latest version of this software
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of an SQL Injection bug in phpBugTracker";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 Noam Rathaus");
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

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

function check(loc)
{
 req = http_get(item:string(loc, "/bug.php?op=vote&bugid=1'"),
 		port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( r == NULL )exit(0);
 if(egrep(pattern:"DB Error: syntax error", string:r) ||
    egrep(pattern:"MySQL server version for", string:r))
 {
 	security_hole(port);
	exit(0);
 }
}

check(loc:"/bugs/");
foreach dir (cgi_dirs())
{
check(loc:dir);
}

