#
# Script by Noam Rathaus GPLv2
#
# YusASP Web Asset Manager Vulnerability
# "eric basher" <basher13@linuxmail.org>
# 2005-05-04 12:23

if(description)
{
 script_id(18192);
 script_version("$Revision: 1.1 $");
 
 name["english"] = "YusASP Web Asset Manager Vulnerability";

 script_name(english:name["english"]);
 
 desc["english"] = "
YusASP Web Asset Manager is a complete file manager for your website.
If left uprotected, the YusASP allows you to anage the remote server's
web folder structure, upload and download files, etc.

Risk factor: High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of a YusASP Web Asset vulnerability";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2005 Noam Rathaus");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl");
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
 req = http_get (item: string(loc, "/editor/assetmanager/assetmanager.asp"), port: port);
 r = http_keepalive_send_recv(port:port, data:req);
 if( r == NULL )exit(0);
 if(egrep(pattern:'input type="hidden" name="inpAssetBaseFolder', string:r))
 {
  security_warning(port);
  exit(0);
 }
}

foreach dir (cgi_dirs())
{
 check(loc:dir);
}

