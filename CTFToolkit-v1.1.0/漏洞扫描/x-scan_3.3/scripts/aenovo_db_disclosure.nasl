#
# (C) Noam Rathaus GPLv2
#
# aeNovo Database Content Disclosure Vulnerability
# From: farhad koosha <farhadkey@yahoo.com>
# Date: 2005-03-12 19:59

if(description)
{
 script_id(17323);
 script_version("$Revision: 1.1 $");
 script_bugtraq_id(12678);
 
 name["english"] = "aeNovo Database Content Disclosure Vulnerability";

 script_name(english:name["english"]);
 
 desc["english"] = "
aeNovo is a web content management system. Due to improper file premission
settings on the database directory it is possible for a remote attacker
to download the product's database file and grab from it sensitive information.

Solution: Restrict access the the aeNovo's database file or directory by setting
file/directory restrictions.

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of DB file of aeNovo";
 
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

debug = 0;

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

function check(loc)
{
 if (debug) { display("loc: ", loc, "\n"); }
 req = http_get(item:string(loc, "/aeNovo1.mdb"), port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly: 1);
 if( r == NULL )exit(0);

 if (debug) { display("r: [", r, "]\n"); }
 if (("Content-Type: application/x-msaccess" >< r) && ('Standard Jet DB' >< r))
 {
  security_hole(port);
  exit(0);
 }
}

foreach dir (make_list("/dbase", "/mdb-database", cgi_dirs()))
{
 check(loc:dir);
}

