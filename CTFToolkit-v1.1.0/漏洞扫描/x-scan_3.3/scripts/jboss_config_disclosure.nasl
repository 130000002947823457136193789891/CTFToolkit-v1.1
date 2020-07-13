#
# (C) Tenable Network Security
# 

if(description)
{
 script_id(18526);
 script_bugtraq_id(13985);
 script_version("$Revision: 1.1 $");
 
 name["english"] = "JBoss Malformed HTTP Request Remote Information Disclosure";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote JBoss server is vulnerable to an information disclosure flaw
which may allow an attacker to retrieve the physical path of the server 
installation, its security policy, or to guess its exact version number.

An attacker may use this flaw to gain more information about the remote
configuration.

Solution : Upgrade to JBoss 3.2.8 or 4.0.3 (when available)
Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Attempts to read security policy of a remote JBoss server";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 8083);
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:8083);
if ( ! port ) exit(0);

req = http_get(item:"%.", port:port);
res = http_keepalive_send_recv(port:port, data:req);
if ( res == NULL ) exit(0);

if ( ereg(pattern:"^HTTP/.* 400 (/|[A-Z]:\\)", string:res) )
{
 req = http_get(item:"%server.policy", port:port);
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
 if ( "JBoss Security Policy" >< res )
 {
  report = "
The remote JBoss server is vulnerable to an information disclosure flaw
which may allow an attacker to retrieve the physical path of the server 
installation, its security policy, or to guess its exact version number.

By requesting '%server.policy' it was possible to extract the following 
security policy :

" + res + "

An attacker may use this flaw to gain more information about the remote
configuration.

Solution : Upgrade to JBoss 3.2.8 or 4.0.3 (when available)
Risk Factor : Medium";
  security_warning(port:port, data:report); 
 }
}
