#
# Copyright 2001 by Noam Rathaus <noamr@securiteam.com>
#
# See the Nessus Scripts License for details
#
#

if(description)
{
 script_id(10737);
 script_version ("$Revision: 1.8 $");

 name["english"] = "Oracle Applications One-Hour Install Detect";
 script_name(english:name["english"]);

 desc["english"] = "We detected the remote web server as an Oracle 
Applications' One-Hour Install web server. This web server enables
attackers to configure your Oracle Application server and Oracle Database 
server without any need for authentication.

Solution: Disable the Oracle Applications' One-Hour Install web server 
after you have completed the configuration, or block the web server's 
port on your Firewall.

Risk factor : High";

 script_description(english:desc["english"]);

 summary["english"] = "Oracle Applications One-Hour Install Detect";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2001 SecuriTeam");
 family["english"] = "General";
 script_family(english:family["english"]);

 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 8002);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
 
port = get_http_port(default:8002);
if (!port) exit(0);


banner = get_http_banner(port:port);
if ( !  banner ) exit(0);

if ("Oracle Applications One-Hour Install" >< banner)
   security_hole(port);
