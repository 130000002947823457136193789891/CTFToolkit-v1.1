#
# (C) Noam Rathaus GPLv2
#
# Multiple vulnerabilities in MercuryBoard 1.1.1
# "Alberto Trivero" <trivero@jumpy.it>
# 2005-01-24 23:37

if(description)
{
 script_id(16247);
 script_version ("$Revision: 1.8 $");
 script_cve_id(
    "CAN-2005-0306",
    "CAN-2005-0307",
    "CAN-2005-0414",
    "CAN-2005-0460",
    "CAN-2005-0462",
    "CAN-2005-0662",
    "CAN-2005-0663"
 );
 script_bugtraq_id(12359, 12503, 12578, 12706, 12707, 12872); 
 if (defined_func("script_xref")) {
   script_xref(name:"OSVDB", value:"13262");
   script_xref(name:"OSVDB", value:"13263");
   script_xref(name:"OSVDB", value:"13264");
   script_xref(name:"OSVDB", value:"13265");
   script_xref(name:"OSVDB", value:"13266");
   script_xref(name:"OSVDB", value:"13267");
   script_xref(name:"OSVDB", value:"13764");
   script_xref(name:"OSVDB", value:"13787");
   script_xref(name:"OSVDB", value:"14307");
   script_xref(name:"OSVDB", value:"14308");
}


 name["english"] = "Multiple Vulnerabilities in MercuryBoard";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running MercuryBoard, a message board system written
in PHP.

Multiple vulnerabilities have been discovered in the product that allow
an attacker to cause numerous cross site scripting attacks, inject
arbitrary SQL statements and disclose the path under which the product
has been installed.

Solution: Upgrade to MercuryBoard version 1.1.3

Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of an old version of mercuryBoard";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Noam Rathaus");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "httpver.nasl", "http_version.nasl");
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

function check(loc)
{
 req = http_get(item:string(loc, "/index.php"), port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly: 1);
 if( r == NULL )exit(0);

 if ( "Powered by <a href='http://www.mercuryboard.com' class='small'><b>MercuryBoard</b></a>" >< r )
 {
  if ( egrep(pattern:'<b>MercuryBoard</b></a> \\[v(0\\..*|1\\.0\\..*|1\\.1\\.[0-2])\\]', string:r) ) 
  {
   security_warning(port);
   exit(0);
  }
 }
}

foreach dir ( cgi_dirs() )
{
 check(loc:dir);
}


