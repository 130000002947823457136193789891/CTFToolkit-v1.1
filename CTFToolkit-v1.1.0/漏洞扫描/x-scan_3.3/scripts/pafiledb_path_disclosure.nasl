# 
# (C) Tenable Network Security
# 
# This script was written by shruti@tenablesecurity.com
# based on the scripts written by Renaud Deraison.
#
# Reference: y3dips
#


if(description)
{
 script_id(15909);
 script_bugtraq_id(11817);
 script_version ("$Revision: 1.3 $");
 
 name["english"] = "PAFileDB Error Message Path Disclosure Vulnerability";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running paFileDB, a PHP based database of files. 
It supports accounts to control the accessibility of these files 
and password protection of downloads.

There is a flaw in it which may let an attacker obtain
the physical path of the remote installation by sending a malformed request
to one of the scripts 'admins.php', 'category.php', or 'team.php'. 

Knowing this information will help an attacker to make more focused
attacks.

Solution : None at this time
Risk factor : Low";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for psFileDB path disclosure";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004-2005 Tenable Network Security");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("pafiledb_detect.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);


# Test an install.
install = get_kb_item(string("www/", port, "/pafiledb"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  req = http_get(item:dir + "/includes/admin/admins.php", port:port);
  res = http_keepalive_send_recv(port:port, data:req);
  if("Fatal error: Call to undefined function" >< res)
  {
    security_note(port);
    exit(0);
  }

  req = http_get(item:dir + "/includes/admin/category.php", port:port);
  res = http_keepalive_send_recv(port:port, data:req);
  if("Fatal error: Call to undefined function" >< res)
  {
    security_note(port);
    exit(0);
  }

  req = http_get(item:dir + "/includes/team.php", port:port);
  res = http_keepalive_send_recv(port:port, data:req);
  if("failed to open stream:" >< res)
  {
    security_note(port);
    exit(0);
  }
}
