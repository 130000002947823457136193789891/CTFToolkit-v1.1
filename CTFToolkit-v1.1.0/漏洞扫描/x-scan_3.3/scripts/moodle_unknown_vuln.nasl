#
# (C) Tenable Network Security
#


if (description)
{
 script_id(13843);
 script_bugtraq_id(10697, 10718, 10766);
 script_version("$Revision: 1.3 $");

 script_name(english:"Moodle < 1.3.3");
 desc["english"] = "
The remote host is running a version of the Moodle PHP suite which is
older than version 1.3.3.

The remote version of this software is vulnerable to a cross site scripting
issue in help.php, as well as to an undisclosed vulnerability in the language
settings management.

Solution : Upgrade to Moodle 1.3.3
Risk factor : High";

 script_description(english:desc["english"]);
 script_summary(english:"Determines if Moodle is older than 1.3.3");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses : XSS", francais:"Abus de CGI");
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

foreach dir ( cgi_dirs() )
{
 req = http_get(item:string(dir, "/help.php?file=<script>foo</script>"), port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if(res == NULL ) exit(0);
 
 if( "Help file '<script>x</script>' could not be found!" >< res )
 {
    	security_warning(port);
	exit(0);
 }
}
