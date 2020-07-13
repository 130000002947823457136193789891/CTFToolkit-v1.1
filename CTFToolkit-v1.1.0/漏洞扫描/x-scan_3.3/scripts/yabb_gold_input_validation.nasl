#
# (C) Tenable Network Security
#

if (description)
{
 script_id(14806);
 script_bugtraq_id(11235);
 script_version ("$Revision: 1.3 $");

 script_name(english:"YaBB Gold 1 Multiple Input Validation Issues");
 desc["english"] = "
The remote host is using the YaBB 1 Gold web forum software.

According to its version number, the remote version of this software
is vulnerable to various input validation issues which may allow an 
attacker to perform a cross site scripting attack or an HTTP splitting
attack against the remote host.

Solution: Upgrade to YaBB 1 Gold SP 1.3.2 or newer
Risk factor : Medium";

 script_description(english:desc["english"]);
 script_summary(english:"Determines the version of YaBB 1 Gold");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses : XSS", francais:"Abus de CGI");
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);


dirs = make_list("/yabb", cgi_dirs(), "/forum");
		

foreach d (dirs)
{
 url = string(d, "/YaBB.pl");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req);
 if( buf == NULL ) exit(0);
 if(egrep(pattern:"Powered by.*YaBB 1 Gold - (Release|SP1(\.[1-2].*|3(\.1)?))", string:buf))
   {
    security_warning(port);
    exit(0);
   }
}
