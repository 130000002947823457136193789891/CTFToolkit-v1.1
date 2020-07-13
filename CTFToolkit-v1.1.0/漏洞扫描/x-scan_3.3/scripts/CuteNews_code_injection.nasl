#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# Ref:
# From: "Over_G" <overg@mail.ru>
# To: vuln@security.nnov.ru, bugtraq@securityfocus.com,
#        staff@packetstormsecurity.org
# Subject: PHP code injection in CuteNews
# Message-Id: <E18ndJT-000JS2-00@f19.mail.ru>



if(description)
{
 script_id(11276);
 script_bugtraq_id(6935);
 if (defined_func("script_xref")) {
   script_xref(name:"OSVDB", value:"5957");
   script_xref(name:"OSVDB", value:"6051");
   script_xref(name:"OSVDB", value:"6052");
 }
 script_version ("$Revision: 1.9 $");
 # script_cve_id("CVE-MAP-NOMATCH");
 # NOTE: no CVE id assigned (jfs, december 2003)

 name["english"] = "CuteNews code injection";

 script_name(english:name["english"]);
 
 desc["english"] = "
It is possible to make the remote host include php files hosted
on a third party server using CuteNews.

An attacker may use this flaw to inject arbitrary code in the remote
host and gain a shell with the privileges of the web server.

Solution : Upgrade to CuteNews 0.89 or newer
Risk factor : High";




 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of search.php";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2003-2005 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003-2005 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("cutenews_detect.nasl", "find_service.nes", "http_version.nasl");
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
if(!can_host_php(port:port)) exit(0);



# Test an install.
install = get_kb_item(string("www/", port, "/cutenews"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
 loc = matches[2];

 req = http_get(item:string(loc, "/search.php?cutepath=http://xxxxxxxx"),
 		port:port);			
 r = http_keepalive_send_recv(port:port, data:req);
 if( r == NULL )exit(0);
 if(egrep(pattern:".*http://xxxxxxxx/config\.php", string:r))
 {
 	security_hole(port);
	exit(0);
 }
}
