#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# Ref: Megasky <magasky@hotmail.com>
# This script is released under the GNU GPLv2
#

if(description)
{
  script_id(18221);
  script_cve_id("CAN-2005-1554");
  script_bugtraq_id(13569);
  if (defined_func("script_xref")) {
    script_xref(name:"OSVDB", value:"16543");
  }

  script_version("$Revision: 1.3 $");
  script_name(english:"wowBB view_user.php SQL Injection flaw");
 
 desc["english"] = "
The remote host is running wowBB, a web based forum  written in PHP.

The remote version of this software is vulnerable to SQL injection attacks 
through the script 'view_user.php'. A malicious user can inject SQL commands 
to be executed on the underlying database.

Solution: Upgraded to the latest version.
Risk factor : Medium";

  script_description(english:desc["english"]);

  script_summary(english:"Checks SQL injection flaw in wowBB");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005 David Maciejak");
  script_family(english:"CGI abuses");
  script_require_ports("Services/www", 80);
  script_dependencie("http_version.nasl");
  exit(0);
}

# the code!

include("http_func.inc");
include("http_keepalive.inc");

function check(req)
{
  buf = http_get(item:string(req,"/view_user.php?list=1&letter=&sort_by='select"), port:port);
  r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
  if( r == NULL )exit(0);
  if (("Invalid SQL query: SELECT" >< r) && (egrep(pattern:"TITLE=.WowBB Forum Software", string:r)))
  {
 	security_warning(port);
	exit(0);
  }
}

port = get_http_port(default:80);
if ( ! port ) exit(0);
if(!get_port_state(port)) exit(0);
if(!can_host_php(port:port))exit(0);

foreach dir ( cgi_dirs() ) check(req:dir);
