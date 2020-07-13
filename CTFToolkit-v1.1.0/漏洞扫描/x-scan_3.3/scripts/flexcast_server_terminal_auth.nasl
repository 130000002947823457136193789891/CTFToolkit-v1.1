#
# (C) Tenable Network Security
#
# 

if (description) {
  script_id(18429);
  script_version("$Revision: 1.1 $");

  script_bugtraq_id(13858);

  name["english"] = "FlexCast Server Terminal Authentication Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
The remote host is running FlexCast, an audio/video streaming server. 

According to its banner, the version installed on the remote host
suffers from a terminal authentication vulnerability.  While details
are as-yet unavailable, it is likely the flaw is remotely exploitable. 

See also : http://freshmeat.net/projects/flexcast/?branch_id=35817&release_id=196787
Solution : Upgrade to FlexCast 2.0 or newer.
Risk factor : Medium";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for terminal authentication vulnerability in FlexCast Server";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencie("http_version.nasl");
  script_require_ports("Services/www", 8000, 8001);

  exit(0);
}


include("http_func.inc");


port = get_http_port(default:8000);
if (!get_port_state(port)) exit(0);


# Check the version number in the banner.
banner = get_http_banner(port:port);
if (
  banner && 
  banner =~ "^Server: FlexCast Server/[01]\."
) {
  security_warning(port);
}
