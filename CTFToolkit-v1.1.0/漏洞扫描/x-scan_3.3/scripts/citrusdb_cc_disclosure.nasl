#
# (C) Noam Rathaus GPLv2
#
# Maximillian Dornseif <dornseif@informatik.rwth-aachen.de>
# 2005-02-13 00:31
# Credit Card data disclosure in CitrusDB

if(description)
{
 script_id(16388);
 script_bugtraq_id(12402);
 script_cve_id("CAN-2005-0229");
 script_version("$Revision: 1.2 $");

 
 name["english"] = "Credit Card Data Disclosure in CitrusDB";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running CitrusDB, an open-source customer database
application written in PHP.

CitrusDB uses a textfile to temporarily store credit card information.
This textfile is located in the web tree via a static URL and thus
accessible to third parties. It also isn't deleted after processing
resulting in a big window of opportunity for an attacker.

Workaround : Either deny access to the file using access restriction 
features of the remote webserver or change CitrusDB to use a file 
outside the document root and not accessible via HTTP.

Solution : Update to CitrusDB version 0.3.6 or higher and set the 
option '$path_to_ccfile' in the configuration to a path not 
accessible via HTTP.

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of IO directory of CitrusDB";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Noam Rathaus");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("http_version.nasl");
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

function check(loc)
{
 req = http_get(item:string(loc, "/newfile.txt"), port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly: 1);
 if( r == NULL )exit(0);

 if ('"CHARGE","' >< r)
 {
  security_hole(port);
  exit(0);
 }
}

foreach dir (make_list("/io", cgi_dirs()))
{
 check(loc:dir);
}

