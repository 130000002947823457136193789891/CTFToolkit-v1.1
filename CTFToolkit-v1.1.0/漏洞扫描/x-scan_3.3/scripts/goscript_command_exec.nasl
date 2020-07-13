#
# (C) Tenable Network Security
#
# osvdb value submitted by David Maciejak
if (description) {
  script_id(14237);
  script_bugtraq_id(10853);
  if ( defined_func("script_xref") ) script_xref(name:"OSVDB", value:"8935");
  script_version ("$Revision: 1.5 $");

  name["english"] = "Goscript command execution";
  script_name(english:name["english"]);
 
  desc["english"] = "
The remote host is running a version of Pete Stein's Goscript
which is vulnerable to a remote command execution flaw.

An attacker, exploiting this flaw, would only need access to 
the webserver.
 
Solution : Upgrade to latest version of Goscript 

See also : http://www.securityfocus.com/bid/10853 
 
Risk factor : High";

  script_description(english:desc["english"]);
 
  summary["english"] = "Goscript command execution detection";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) Tenable Network Security");
  family["english"] = "CGI abuses";
  script_family(english:family["english"]);

  script_require_ports("Services/www", 80);
  script_dependencies("http_version.nasl");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if (!get_port_state(port)) 
	exit(0);

foreach dir (make_list(cgi_dirs()))
{
	req = http_get(item:string(dir, "/go.cgi|id|"), port:port);
	r   = http_keepalive_send_recv(port:port, data:req);
	if ( ! r ) exit(0);
	if (egrep(pattern:"uid=[0-9]* gid=[0-9]*", string:r) )
		security_hole(port);
}


