#
# (C) Tenable Network Security
#
# 

if(description)
{
 script_id(12095);
 script_bugtraq_id(9861);
 
 script_version("$Revision: 1.2 $");
 name["english"] = "Emumail WebMail multiple vulnerabilities";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a version of Emumail EMU WebMail which is older or as
old as 5.2.7.

There are several flaws in this version, ranging from information disclosure to
cross site scripting vulnerabilties which may allow an attacker to trick
a logged user or to gain more information about this system.

Solution : Upgrade to the latest version of this software
Risk factor : Medium";


 script_description(english:desc["english"]);
 
 summary["english"] = "version test for vHost";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");

function check(dir)
{
  req = http_get(item:dir + "/emumail.fcgi" + time, port:port);
  res = http_keepalive_send_recv(port:port, data:req);
  if ( res == NULL ) exit(0);

  if ("Powered by EMU Webmail" >< res )
   {
    if ( egrep(pattern:"Powered by EMU Webmail ([0-4]\.|5\.([01]\.|2\.[0-7][^0-9]))", string:res) ) {
	security_warning(port);
	exit(0);
    }
   }
 return(0);
}

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);


foreach dir ( cgi_dirs() )
{
 check(dir:dir);
}
