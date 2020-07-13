#
# (C) Tenable Network Security
#

if(description)
{
 script_id(12101);
 script_bugtraq_id(9822);
 script_version ("$Revision: 1.5 $");
 
 name["english"] = "Invision PowerBoard XSS";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using Invision Power Board.

There is a bug in this software which makes it vulnerable to cross site
scripting attacks.

An attacker may use this bug to steal the credentials of the legitimate users
of this site.

Solution : At this time, the vendor did not supply any patch
Risk factor : High";




 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of an XSS bug in Invision PowerBoard";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 - 2005 Tenable Network Security");
 family["english"] = "CGI abuses : XSS";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "cross_site_scripting.nasl", "http_version.nasl", "invision_power_board_detect.nasl");
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
if(!can_host_php(port:port))exit(0);
if (  get_kb_item(string("www/", port, "/generic_xss")) ) exit(0);


# Check each installed instance, stopping if we find a vulnerability.
installs = get_kb_list(string("www/", port, "/invision_power_board"));
if (isnull(installs)) exit(0);
foreach install (installs) {
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches)) {
    ver = matches[1];
    dir = matches[2];

    req = http_get(item:string(dir, "/index.php?s=&act=chat&pop=1;<script>foo</script>"),
 		port:port);
    r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
    if( r == NULL )exit(0);
    if(egrep(pattern:"<script>foo</script>", string:r))
    {
 	security_warning(port);
	exit(0);
    }
  }
}
