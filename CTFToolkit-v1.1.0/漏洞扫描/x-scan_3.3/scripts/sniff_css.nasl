#
# (C) Noam Rathaus
#
# Ref: 
# From: Justin Hagstrom [justinhagstrom@yahoo.com]
# To: news@securiteam.com
# Subject: Snif Script Cross Site Scripting Vulnerability
# Date: Tuesday 09/12/2003 02:40
#
# Changes by rd: description
#


if(description)
{
 script_id(11949);
 script_bugtraq_id(9179);
 script_version ("$Revision: 1.6 $");
 name["english"] = "Snif Cross Site Scripting";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running the 'Snif' CGI suite. There is a vulnerability in
it which may allow an attacker to insert a malicious HTML and/or Javascript
snipet in the response returned to a third party user (this problem is
known as a cross site scripting bug).


Solution: None at this time - disable this CGI suite
Risk factor: Medium";



 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the Snif Cross Site Scripting";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Noam Rathaus");
 family["english"] = "CGI abuses : XSS";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
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

foreach dir ( cgi_dirs() )
{
 req = http_get(item:dir + "/index.php?path=<script>malicious_code</script>", port:port);
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if ( res == NULL ) exit(0);

 if (egrep(pattern:"<script>malicious_code</script></title>", string:res)) { security_warning(port); exit(0); }
}
