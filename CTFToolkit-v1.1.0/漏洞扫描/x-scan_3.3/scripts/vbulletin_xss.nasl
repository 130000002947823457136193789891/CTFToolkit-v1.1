#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
#  (C) Tenable Network Security
#
#  Ref: Cheng Peng Su
#
#  This script is released under the GNU GPL v2


if(description)
{
 script_id(14792);
 script_bugtraq_id(10612, 10602);
 if ( defined_func("script_xref") ) script_xref(name:"OSVDB", value:"7256");
 script_cve_id("CAN-2004-0620");
  
 script_version("$Revision: 1.5 $");
 name["english"] = "vBulletin XSS";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running vBulletin, a web based bulletin board system 
written in PHP.

The remote version of this software is vulnerable to a cross-site scripting 
issue, due to a failure of the application to properly sanitize user-supplied 
URI input.

As a result of this vulnerability, it is possible for a remote attacker
to create a malicious link containing script code that will be executed 
in the browser of an unsuspecting user when followed. 

This may facilitate the theft of cookie-based authentication credentials 
as well as other attacks.


Solution : Upgrade to vBulletin 3.0.2 or newer
Risk factor : Medium";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the version of vBulletin";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 family["english"] = "CGI abuses : XSS";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl", "vbulletin_detect.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");



port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if ( ! can_host_php(port:port) ) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/vBulletin"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];
  if ( ver =~ '3.0(\\.[01])?[^0-9]' ) security_warning(port);
}
