#
# (C) Tenable Network Security
#

if(description)
{
 script_id(12058);
 script_bugtraq_id(9649, 9656);
 script_version ("$Revision: 1.5 $");

 
 name["english"] = "JelSoft VBulletin XSS";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running JelSoft VBulletin.

There is a cross site scripting issue in this CGI suite which may allow an 
attacker to steal your users cookies.


Solution : None at this time - contact the vendor
Risk factor : Medium";




 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for JelSoft VBulletin";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2004-2005 Tenable Network Security"); 
 family["english"] = "CGI abuses : XSS";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl", "cross_site_scripting.nasl", "vbulletin_detect.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# The script code starts here

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);
if(!can_host_php(port:port))exit(0);

# Test an install.
install = get_kb_item(string("www/", port, "/vBulletin"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
 d = matches[2];
 req = http_get(item:string(d, "/search.php?do=process&showposts=0&query=<script>foo</script>"), port:port);
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( res == NULL ) exit(0);
 if( egrep(pattern:"<script>foo</script>", string:res) ) security_warning(port);
}
