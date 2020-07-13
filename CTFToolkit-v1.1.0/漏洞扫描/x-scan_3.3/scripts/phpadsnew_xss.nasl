#
# Script by Noam Rathaus GPLv2
#
# phpAdsNew 2.0.4-pr1 Multiple vulnerabilities cXIb8O3.9
# From: Maksymilian Arciemowicz <max@jestsuper.pl>
# Date: 2005-03-15 03:56
#
# Changes by Tenable:
#  - Added a BID
#  - Added script_version()
#
#
if(description)
{
 script_id(17335);
 script_version("$Revision: 1.2 $");
 script_cve_id("CAN-2005-0791");
 script_bugtraq_id(12803);
 
 name["english"] = "phpAdsNew Multiple Vulnerabilities";

 script_name(english:name["english"]);
 
 desc["english"] = "
phpAdsNew is an open-source ad server, with an integrated banner
management interface and tracking system for gathering statistics.
With phpAdsNew you can easily rotate paid banners and your own
in-house advertisements. You can even integrate banners from
third party advertising companies.

The product has been found to contain two vulnerabilities:
 * Path disclosure vulnerability
 * Cross Site Scripting

An attacker may use the cross site scripting bug to preform phishing
attacks.

Risk factor: Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of a XSS in phpAdsNew";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2005 Noam Rathaus");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "cross_site_scripting.nasl", "http_version.nasl");
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

debug = 0;

function check(loc)
{
 req = http_get(item: string(loc, "/adframe.php?refresh=example.com'<script>alert(document.cookie)</script>"), port:port);
 r = http_keepalive_send_recv(port:port, data:req);
 if( r == NULL )exit(0);
 if("content='example.com\'><script>alert(document.cookie)</script>'>" >< r)
 {
  security_warning(port);
  exit(0);
 }
}

foreach dir ( cgi_dirs() ) check(loc:dir);
