#
# (C) Tenable Network Security
#

if (description)
{
 script_id(16095);
 script_cve_id("CAN-2005-0267", "CAN-2005-0268");
 script_bugtraq_id(12150);
 script_version("$Revision: 1.2 $");
 script_name(english:"FlatNuke Form Submission Input Validation Vulnerability");
 desc["english"] = "
The remote host is running FlatNuke, a database-less content management system
written in PHP.

The remote version of this software is vulnerable to a form submission
vulnerability which may allow an attacker to execute arbitrary PHP commands
on the remote hose.

Solution : Upgrade to the latest version of FlatNuke
Risk factor : High";

 script_description(english:desc["english"]);
 script_summary(english:"Determines if FlatNuke is installed");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses", francais:"Abus de CGI");
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);

if(!get_port_state(port))exit(0);


foreach dir ( cgi_dirs() )
{
req = http_get(item:string(dir, "/index.php"), port:port);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
if(res == NULL ) exit(0);

if ( 'Powered by <b><a href="http://flatnuke.sourceforge.net">' >< res )
{
 str = chomp(egrep(pattern:'Powered by <b><a href="http://flatnuke.sourceforge.net">', string:res));
 version = ereg_replace(pattern:".*flatnuke-([0-9.]*).*", string:str, replace:"\1");
 if ( dir == "" ) dir = "/";
 set_kb_item(name:"www/" + port + "/flatnuke", value: version + " under " + dir);

 if ( ereg(pattern:"^([0-1]\.|2\.([0-4]\.|5\.[0-1][^0-9]))", string:version) )
 	{
	security_hole ( port );
	exit(0);
	}
 }
}

