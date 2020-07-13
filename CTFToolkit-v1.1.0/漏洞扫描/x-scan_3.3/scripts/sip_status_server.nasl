if(description)
{
 script_id(11945);
 script_version("$Revision: 1.6 $");
#script_cve_id("CVE-MAP-NOMATCH");
 name["english"] = "sxdesign SIPd Status Server Detection";
 script_name(english:name["english"]);
 
 desc["english"] = "A SIP status server is running on this port.

An attacker may use the remote status information of this server to
collect sensitive information such as server version, emails, 
and ip addresses (internal and external).

Solution: Access to this port should be restricted to trusted users only
Risk Factor: Low";

 script_description(english:desc["english"]);
 summary["english"] = "SIP Status Server Detection";
 script_summary(english:summary["english"]);
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Noam Rathaus");
 family["english"] = "Misc.";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl");
 script_require_ports("Services/www", 6050);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:6050);
if(!port)exit(0);

res = http_get_cache(item:"/", port:port);
if ( res == NULL ) exit(0);
if ("SIP Server Status" >< res && "Server Version" >< res) security_note(port);
