#
# Script by Noam Rathaus
#
# From: Janek Vind <come2waraxe@yahoo.com>
# Subject: [waraxe-2004-SA#024 - XSS and full path disclosure in Network Query Tool 1.6]
# Date: 2004-04-24 04:20

if(description)
{
 script_id(12223);
 script_version ("$Revision: 1.4 $"); 
 name["english"] = "Network Query Tool XSS";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using Network Query Tool. There is a bug in this 
software that makes it vulnerable to cross site scripting attacks.

An attacker may use this bug to steal the credentials of the legitimate 
users of this site.

Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of an XSS bug in NQT";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Noam Rathaus");
 family["english"] = "CGI abuses : XSS";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "cross_site_scripting.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

function check(loc)
{
 req = http_get(item:string(loc, "/nqt.php?target=127.0.0.1&queryType=all&portNum=foobar%3Cscript%3Efoo%3C/script%3E"),
                port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( r == NULL )exit(0);
 if(egrep(pattern:"<script>foo</script>", string:r))
 {
        security_warning(port);
        exit(0);
 }
}


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);
if (  get_kb_item(string("www/", port, "/generic_xss")) ) exit(0);

check(loc:"/nqt");
foreach dir (cgi_dirs())
{
 check(loc:dir);
}

