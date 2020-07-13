#
# This script was written by Noam Rathaus
#
# Subject: 3com NBX VOIP NetSet Denial of Service Attack
# Date: 2004-04-29 23:34
# From: Michael Scheidell SECNAP Network Security
#
# mods by above named Michael Scheidell:
# change to ACT_GATHER_INFO (this plugin doesn't relaly do any attacks)
# if safe_checks() enabled, set host to DEAD! so that other plugins don'k
# kill it.

if(description)
{
 script_id(12221);
 script_cve_id("CAN-2004-1977");
 script_bugtraq_id(10240);
 script_version ("$Revision: 1.10 $");
 name["english"] = "3Com NBX VoIP NetSet Detection";
 script_name(english:name["english"]);
 
 desc["english"] = "We have discovered that 3Com NBX VOIP NetSet is running 
on the remote host.  3Com NBX VoIP NetSet's web server is powered by VxWorks.
The web server is known to contain vulnerabilities that would allow a remote
attacker to cause a denial of service against the product by simply running
a port scanning/vulnerability scanning engine against it.

Problems have been observed in Netset 4.2.7, bur previous 4.1 versions
seem to be ok.

See Also :  http://www.secnap.com/security/20040420.html
Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Tests for 3Com NBX VoIP NetSet Detection";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Noam Rathaus");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_kb_item("Services/www");
if(!port)port = 80;
if(get_port_state(port))
{ 
 r   = http_get_cache(item:"/", port:port);
 if ( ! r ) exit(0);
 if("sysObjectID" >< r && "1.3.6.1.4.1.43.1.17" >< r)
 {
 	security_hole(port);
 	if(safe_checks()) set_kb_item(name:"Host/dead", value:TRUE);
 }
}

