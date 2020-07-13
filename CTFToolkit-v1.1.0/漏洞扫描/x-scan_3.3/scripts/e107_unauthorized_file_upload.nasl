exit(0); # Broken (version detection needs to be fixed)
#
# (C) Tenable Network Security
#

if(description)
{
 script_id(16061);
 script_bugtraq_id(12111);
 script_version("$Revision: 1.2 $");
 name["english"] = "e107 Image Manager Unauthorized File Upload";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running the 'e107' web content management system written
in PHP.

There is a flaw in the remote version of this web site which may allow certain
users to upload arbitrary files on the remote host.

An attacker may exploit this flaw to upload a PHP file to the remote host
containing arbitrary commands and have the remote web server execute it when
attempting to display it.

Solution : Upgrade to e107 0.617 or newer
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "e107 flaw";
 
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
if( ! can_host_php(port:port) ) exit(0);
foreach dir (make_list("/e107", cgi_dirs()))
{
 req = http_get(item:dir + "/upgrade.php", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);
 if ( "Upgrade complete," >< res )
 {
  line = chomp(egrep(pattern:"Upgrade complete, now running", string:res));
  if ( ! line ) exit(0);
  
  version = ereg_replace(pattern:".*Upgrade complete, now running v([0-9.]*)\..*", string:line, replace:"\1");
  if ( dir == "" ) dir = "/";
  set_kb_item(name:"www/" + port + "/e107", value:version + " under " + dir );
  if ( ereg(pattern:"^0\.([0-5]|60|61[0-6]\.)", string:version) )
	{
	 security_hole(port);
	 exit(0);
	}
 }
}
