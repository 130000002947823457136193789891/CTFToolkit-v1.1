#
# (C) Tenable Network Security
#
#
# Ref:
#  Date: 17 May 2003 13:18:59 -0000
#  From: Lorenzo Manuel Hernandez Garcia-Hierro <security@lorenzohgh.com>
#  To: bugtraq@securityfocus.com
#  Subject: Path Disclosure in Turba of Horde
#
#

if (description)
{
 script_id(11646);
 script_version ("$Revision: 1.6 $");

 script_bugtraq_id(7622);

 script_name(english:"Turba Path Disclosure");
 desc["english"] = "
The remote host is using Turba, a component of the Horde
Webmail system.

There is a flaw in the file 'status.php' of this CGI which
may allow an attacker to retrieve the physical path of the
remote web root.


Solution : Properly set the options 'display_errors' and 'log_errors' in your php.ini
to avoid to have php display its errors on the web pages it produces.
Risk factor : Low";

 script_description(english:desc["english"]);
 script_summary(english:"Checks for status.php");
 script_category(ACT_ATTACK);
 script_family(english:"CGI abuses", francais:"Abus de CGI");
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 script_dependencie("horde_detect.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/horde"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
 d = matches[2];
 url = string(d, '/turba/status.php');
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req);
 if( buf == NULL ) exit(0);
 
 if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 .*", string:buf) &&
    egrep(pattern:"/turba/status.php3? on line", string:buf))
   {
    security_warning(port);
   }
}
