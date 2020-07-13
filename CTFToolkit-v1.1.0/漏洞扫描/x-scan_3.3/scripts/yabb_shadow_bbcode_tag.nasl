#
# (C) Tenable Network Security
#

if (description)
{
 script_id(15859);
 script_bugtraq_id(11764);
 script_version ("$Revision: 1.1 $");

 script_name(english:"YaBB Shadow BBCode Tag JavaScript Injection Issue");
 desc["english"] = "
The remote host is using the YaBB web forum software.

According to its version number, the remote version of this software
is vulnerable to javascript injection issues using shadow or glow tags.
This may allow an attacker to inject hostile JavaScript into the 
forum system, to steal cookie credentials or misrepresent site content.
When the form is submitted the malicious JavaScript will be incorporated 
into dynamically generated content.

Solution: Upgrade to YaBB 1 Gold SP 1.4
Risk factor : Medium";

 script_description(english:desc["english"]);
 script_summary(english:"Determines the version of YaBB");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses", francais:"Abus de CGI");
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
 if(egrep(pattern:"Powered by.*YaBB (1 Gold - (Release|SP1(\.[1-2].*|3(\.(1|2))?)))", string:buf) ||
    egrep(pattern:"Powered by.*YaBB (1\.([0-9][^0-9]|[0-3][0-9]|4[0-1])(\.0)?)",string:buf) ||
    egrep(pattern:"Powered by.*YaBB (9\.([0-1][^0-9]|1[0-1])(\.[0-9][^0-9]|[0-9][0-9][^0-9]|[0-9][0-9][0-9][^0-9]|[0-1][0-9][0-9][0-9][^0-9]|2000)?)",string:buf))	
   {
    security_warning(port);
    exit(0);
   }
}
