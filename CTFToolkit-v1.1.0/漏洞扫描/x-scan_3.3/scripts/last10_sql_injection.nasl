#
# (C) Noam Rathaus GPLv2
#

if(description)
{
 script_id(16043);
 script_version("$Revision: 1.1 $");
 script_bugtraq_id(11825);
 
 name["english"] = "vBulletin last10.php SQL Injection";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running last10.php, an unofficial plugin
for vBulletin which allows users to add a revolving ticker 
showing the last10 topics of his/her forum.

This set of script may allow an attacker to cause an SQL
Injection vulnerability allowing an attacker to cause the
program to execute arbitrary SQL statements.

Solution : Upgrade to the latest version of this software or disable it
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of an SQL and Last10";
 
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

debug = 0;

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

function check(loc)
{
 if (debug) { display("loc: ", loc, "\n"); }
 req = http_get(item:string(loc, "/last10.php?ftitle='"), port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly: 1);
 if( r == NULL )exit(0);

 if (debug) { display("r: [", r, "]\n"); }
 if(("You have an error in your SQL syntax" >< r) ||
   ("WHERE thread.lastposter=" >< r))
 {
 	security_hole(port);
	exit(0);
 }
}

dirs = make_list(cgi_dirs(), "/forum");

foreach dir (dirs)
{
 check(loc:dir);
}

