#
# (C) Noam Rathaus
#
# This script is released under the GPLv2
#

if(description)
{
 script_id(16022);
 script_cve_id("CAN-2004-1412", "CAN-2004-1413");
 script_bugtraq_id(12037);
 script_version("$Revision: 1.3 $");
 
 name["english"] = "Kayako eSupport SQL Injection and Cross-Site-Scripting";

 script_name(english:name["english"]);
 
 desc["english"] = "
Kayako eSupport is one of the most feature packed support systems; in this 
tour you will find why over a thousand companies have decided to opt for 
eSupport and use it to process their daily support requests. 

This set of scripts may allow an attacker to cause an SQL
Injection vulnerability and a Cross Site Scripting in the program
allowing an attacker to cause the program to execute arbitrary
SQL statements and/or arbitrary JavaScript code.

Solution : Upgrade to the newest version of this software
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of an SQL and XSS in Kayako";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2004 Noam Rathaus");
 family["english"] = "CGI abuses : XSS";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("cross_site_scripting.nasl");
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

if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

function check(loc)
{
 req = http_get(item:string(loc, "/index.php?_a=knowledgebase&_j=search&searchm=<script>foo</script>"), port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly: 1);
 if( r == NULL )exit(0);

 if("<script>foo</script>" >< r)
 {
 	security_hole(port);
	exit(0);
 }
}

dirs = make_list(cgi_dirs(), "/support/esupport", "/support");

foreach dir (dirs)
{
 check(loc:dir);
}
