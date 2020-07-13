#
# Script by Noam Rathaus
#
# From: "DarkBicho" <darkbicho@fastmail.fm>
# Subject: Cross-Site Scripting CuteNews
# Date: 28.6.2004 03:39

if(description)
{
 script_id(12291);
 script_version("$Revision: 1.7 $");

 script_cve_id("CAN-2004-0660");
 script_bugtraq_id(10620, 10750);
 if (defined_func("script_xref")) {
   script_xref(name:"OSVDB", value:"7283");
   script_xref(name:"OSVDB", value:"7284");
   script_xref(name:"OSVDB", value:"7285");
   script_xref(name:"OSVDB", value:"7286");
 }
 
 name["english"] = "CuteNews show_news.php XSS";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using CuteNews - a news management system written in PHP.

There is a bug in this software which makes it vulnerable to cross site 
scripting attacks.

An attacker may use this bug to steal the credentials of the legitimate users
of this site.

Solution : Upgrade to the latest version of this software
Risk factor: Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of an XSS bug in CuteNews";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2004 Noam Rathaus");
 family["english"] = "CGI abuses : XSS";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("cutenews_detect.nasl", "cross_site_scripting.nasl", "http_version.nasl");
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
if (  get_kb_item(string("www/", port, "/generic_xss")) ) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/cutenews"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  loc = matches[2];
 req = http_get(item:string(loc, "/show_news.php?subaction=showcomments&id=%3Cscript%3Efoo%3C/script%3E&archive=&start_from=&ucat="),
 		port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( r == NULL )exit(0);
 if(egrep(pattern:"<script>foo</script>", string:r))
 {
 	security_warning(port);
	exit(0);
 }
}
