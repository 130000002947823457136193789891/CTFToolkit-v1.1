#
# (C) Tenable Network Security
#
#
# Ref:
#  Date: Tue, 8 Jun 2004 13:41:11 +0200 (CEST)
#  From: Fernando Sanchez <fer@ceu.fi.udc.es>
#  To: bugtraq@securityfocus.com
#  Subject: U.S. Robotics Broadband Router 8003 admin password visible


if(description)
{
 script_id(12272);
 script_bugtraq_id(10490);
 script_version("$Revision: 1.1 $");
 name["english"] = "US Robotics Disclosed Password Check";
 script_name(english:name["english"]);
 desc["english"] = "
The remote host seems to be a US Robotics Broadband router.

There is a flaw in the web interface of this device which make it
disclose the administrative password in the file /menu.htm.

Solution: Contact vendor for a fix.  As a temporary workaround,
disable the webserver or filter the traffic to the webserver via an 
upstream firewall.

Risk factor : High";

 script_description(english:desc["english"]);

 summary["english"] = "US Robotics Password Check";

 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");

 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}


# start check


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port)) exit(0); 

req = http_get(item:"/menu.htm", port:port);
res = http_keepalive_send_recv(port:port, data:req);
if ( res == NULL ) exit(0);

if ("function submitF" >< res &&
    "loginflag =" >< res &&
    "loginIP = " >< res &&
    "pwd = " >< res ) security_hole(port);

