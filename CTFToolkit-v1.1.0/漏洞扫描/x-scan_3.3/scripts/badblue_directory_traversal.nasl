if(description)
{
 script_id(10872);
 script_version("$Revision: 1.16 $");

 script_cve_id("CAN-2002-1684");
 script_bugtraq_id(3913);

 name["english"] = "BadBlue Directory Traversal Vulnerability";
 script_name(english:name["english"]);
 
 desc["english"] = "
A security vulnerability in BadBlue allows attackers to access 
files that would otherwise be inaccessible using a directory 
traversal attack.

Solution: Contact the vendor for a patch.
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "BadBlue Directory Traversal Vulnerability";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002 SecurITeam");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "no404.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/badblue");
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

banner = get_http_banner(port:port);
if ( "BadBlue" >!< banner ) exit(0);

if(! get_port_state(port)) exit(0);

cginameandpath[0] = string("/...//...//...//...//...//...//...//...//...//...//...//...//...//windows//win.ini");
cginameandpath[1] = string("/...//...//...//...//...//...//...//...//...//...//...//...//...//winnt//win.ini");

for (i=0; i < 2; i++)
{ 
  u = cginameandpath[i];
  if(check_win_dir_trav_ka(port: port, url:u))
  {
    security_hole(port);
    exit(0);
  }
}
