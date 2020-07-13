#
# (C) Noam Rathaus GPLv2
#

if(description)
{
 script_id(16101);
 script_version("$Revision: 1.2 $");

 script_cve_id("CAN-2005-0273", "CAN-2005-0274");
 script_bugtraq_id(12156, 12157);
 if (defined_func("script_xref")) {
  script_xref(name:"OSVDB", value:"12741");
  script_xref(name:"OSVDB", value:"12742");
 }
 
 name["english"] = "PhotoPost showgallery.php SQL Injection";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote version of PhotoPost PHP contains a vulnerability in the file
'showgallery.php' which allows a remote attacker to cause the program to
execute arbitrary SQL statements against the remote database. 

See also : http://www.gulftech.org/?node=research&article_id=00063-01032005

Solution : Upgrade to the newest version of this software.
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of an SQL injection in showgallery.php";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2005 Noam Rathaus");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("photopost_detect.nasl");
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

# Test an install.
install = get_kb_item(string("www/", port, "/photopost"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
 loc = matches[2];
 req = http_get(item:string(loc, "/showgallery.php?cat=1'"), port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly: 1);
 if(r && "SELECT id,catname,description,photos" >< r) 
 	security_hole(port);
}
