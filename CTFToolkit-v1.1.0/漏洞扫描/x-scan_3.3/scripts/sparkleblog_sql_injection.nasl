#
# (C) Noam Rathaus GPLv2
#
# From: Kovaics Laszla <bugtracklist@freemail.hu>
# Date: 2005-01-15 18:37
# Subject: Various Vulnerabilities in SparkleBlog

if(description)
{
 script_id(16177);
 script_version("$Revision: 1.1 $");
 script_bugtraq_id(12272);
 
 name["english"] = "SparkleBlog SQL Injection";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running SparkleBlog, a web blog manager written in PHP.

The remote version of this software contains a flaw in the file 'journal.php'
which may allow an attacker to insert arbitrary SQL statements in the remote
database.

Solution : Upgrade to the newest version of this software or disable it.
Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of an SQL injection in id parameter";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2005 Noam Rathaus");
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
 req = http_get(item:string(loc, "/journal.php?id='"), port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly: 1);
 if( r == NULL )exit(0);

 if ("SELECT * FROM php_blog WHERE id=" >< r)
 {
 	security_hole(port);
	exit(0);
 }
}

foreach dir ( cgi_dirs() )
{
 check(loc:dir);
}

