#
# (C) Noam Rathaus GPLv2
#

if(description)
{
 script_id(16056);
 script_version("$Revision: 1.1 $");
 
 name["english"] = "phpMyChat Information Disclosure";

 script_name(english:name["english"]);
 
 desc["english"] = "
phpMyChat is an easy-to-install, easy-to-use multi-room
chat based on PHP and a database, supporting MySQL,
PostgreSQL, and ODBC.

This set of script may allow an attacker to cause an information
disclosre vulnerability allowing an attacker to cause the
program to reveal the SQL username and password, the phpMyChat's
administrative password, and other sensitive information.

See also : http://www.securiteam.com/unixfocus/6D00S0KC0S.html
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of an Information Disclosure in phpMyChat";
 
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
 req = http_get(item:string(loc, "/setup.php3?next=1"), port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly: 1);
 if( r == NULL )exit(0);

 if (debug) { display("r: [", r, "]\n"); }
 if(("C_DB_NAME" >< r) || ("C_DB_USER" >< r) || ("C_DB_PASS" >< r))
 {
 	security_hole(port);
	exit(0);
 }
}

dirs = make_list(cgi_dirs(), "/forum", "/forum/chat", "/chat", "/chat/chat", ""); # The /chat/chat isn't a mistake

foreach dir (dirs)
{
 check(loc:dir);
}

