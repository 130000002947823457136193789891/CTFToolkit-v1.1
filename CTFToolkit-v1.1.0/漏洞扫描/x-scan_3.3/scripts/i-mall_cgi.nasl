#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
#  Ref: ZetaLabs, Zone-H Laboratories
#
#  This script is released under the GNU GPL v2
#

if(description)
{
 script_id(15750);
 script_bugtraq_id(10626);
 if ( defined_func("script_xref") ) script_xref(name:"OSVDB", value:"7461");
 
 script_version ("$Revision: 1.2 $");
 name["english"] = "i-mall.cgi";
 script_name(english:name["english"]);
 
 desc["english"] = "
The script i-mall.cgi is installed. Some versions is vulnerable to
remote command exacution flaw, due to insuficient user input sanitization.

A malicious user can pass arbitrary shell commands on the remote server threw
this script.

*** Warning : Nessus solely relied on the presence of this CGI, it did not
*** determine if you specific version is vulnerable to that problem

Solution : None at this time.
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of i-mall.cgi";
 summary["francais"] = "Vérifie la présence de i-mall.cgi";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# The script code starts here
include("http_func.inc");
include("http_keepalive.inc");
port = get_http_port(default:80);

req = http_get(item:"/i-mall/i-mall.cgi?p=|id|", port:port);
res = http_keepalive_send_recv(port:port, data:req);
if ( res == NULL ) exit(0);
if ( egrep(pattern:"uid=[0-9].* gid=[0-9]*", string:res) ) security_hole(port);
