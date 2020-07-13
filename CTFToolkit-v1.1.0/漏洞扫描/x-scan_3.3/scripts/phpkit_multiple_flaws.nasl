#
# (C) Tenable Network Security
#
if(description)
{
 script_id(15784);
 script_cve_id("CAN-2004-1537", "CAN-2004-1538");
 script_bugtraq_id(11725);

 script_version("$Revision: 1.2 $");
 name["english"] = "PHP-Kit Multiple Input Validations";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running PHP-Kit, an open-source content management
system written in PHP.

The remote version of this software is vulnerable to multiple flaws
which may allow an attacker to execute arbitrary SQL statements against
the remote database or to perform a cross site scripting attack using
the remote host.

Solution : Upgrade to the newest version of PHP-Kit
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "SQL Injection";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

loc = make_list();

# 1. Detect phpkit
#foreach dir (cgi_dirs())
dir = "/phpkit";
{
 req = http_get(item:dir + "/include.php", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);
 line = egrep(pattern:".*PHPKIT.* Version [0-9.]*", string:res);
 if ( line )
 {
  version = ereg_replace(pattern:".*PHPKIT.* Version ([0-9.]*).*", string:line, replace:"\1");
  if ( version == line ) version = "unknown";
  if ( dir == "" ) dir = "/";

  set_kb_item(name:"www/" + port + "/phpkit", value:version + " under " + dir);
  loc = make_list(dir, loc);
 }
}

# Now check the SQL injection

foreach dir (loc)
{
 req = http_get(item:dir + "/popup.php?img=<script>", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if  ( 'ALT="<script>" SRC="<script>"' >< res ) 
	{
	security_hole(port);
	exit(0);
	}
 req = http_get(item:loc + "/include.php?path=guestbook/print.php&id='", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if  ( "SELECT * FROM phpkit_gbook WHERE gbook_id='''" >< res )
	{
	security_hole(port);
	exit(0);
	}
}
