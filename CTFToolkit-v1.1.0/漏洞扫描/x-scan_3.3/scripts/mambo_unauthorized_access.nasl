#
# (C) Tenable Network Security
#

if(description)
{
 script_id(16312);
 script_bugtraq_id(12436);
 script_version("$Revision: 1.3 $");
 
 name["english"] = "Mambo Global Variables Unauthorized Access";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote version of Mambo Open Source contains a vulnerability which
may allow a remote attacker to gain unauthorized access to the system. 
This arises due to improper implementation of global variables and not
sanitizing the user-supplied input data. 

Solution : Upgrade to patched version 4.5.1b.
Risk factor: High";
 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for index.php malformed request vulnerability";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "CGI abuses";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("mambo_detect.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/mambo_mos"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
 dir = matches[2];

 req = http_get(item:string(dir, "/index.php?GLOBALS[mosConfig_absolute_path]=http://xxx."), port:port);
 r = http_keepalive_send_recv(port:port, data: req, bodyonly:1);
 if( r == NULL )exit(0);
 if( "http://xxx./includes/HTML_toolbar.php" >< r )
 	security_hole(port);
}
