#
# (C) Tenable Network Security
#

if(description)
{
 script_id(16478);
 script_bugtraq_id(12573);
 script_version("$Revision: 1.2 $");

 name["english"] = "DCP-Portal Multiple SQL Injection Vulnerabilities";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a version of DCP-Portal which is reported
prone to a remote SQL Injection flaw.  

An attacker, exploiting this flaw, would be able to execute commands,
view data, and manipulate data by sending malformed HTTP requests to
the webserver.

Solution : Upgrade to DCP-Portal 6.1.2 or higher.
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of DCP-Portal";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 script_family(english:"CGI abuses");
 
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! port ) exit(0);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

function check(url)
{
 req = http_get(item:url + "/index.php", port:port);

 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);
 if ( egrep (pattern:"</a> Powered by <a href=.*www\.dcp-portal\.org.*DCP-Portal v([0-5]\.|6\.(0|1([^0-9\.]|\.[0-1][^0-9])))", string:res) )
 {
        security_hole(port);
        exit(0);
 }
}


foreach dir ( cgi_dirs() )
{
  check(url:dir);
}

