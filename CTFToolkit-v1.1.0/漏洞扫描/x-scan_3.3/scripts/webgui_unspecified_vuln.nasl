#
# (C) Tenable Network Security
#

if(description)
{
 script_id(15787);
 script_bugtraq_id( 11727 );
 script_version("$Revision: 1.2 $");
 
 name["english"] = "WebGUI Unspecified Vulnerability";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running WebGUI, a content management framework.

The remote version of this software is vulnerable to an undisclosed
remote vulnerability.

See also : http://sourceforge.net/project/shownotes.php?release_id=284011
Solution : Upgrade to WebGUI 6.2.9 or newer
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the version of WebGUI";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if (!get_port_state(port)) exit(0);

res = http_get_cache(item:"/", port:port);
if ( res == NULL ) exit(0);

if ( 'content="WebGUI' >< res && egrep(pattern:".*meta name=.generator.*content=.WebGUI ([0-5]\.|6\.([01]\.|2\.[0-8][^0-9]))", string:res) )
  security_hole(port);
