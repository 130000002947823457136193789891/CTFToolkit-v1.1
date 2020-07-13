#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  This script is released under the GNU GPL v2
#

if(description)
{
 script_id(16280);
 if ( defined_func("script_xref") ) script_xref(name:"OSVDB", value:"13150");
  
 script_version("$Revision: 1.3 $");
 name["english"] = "vBulletin XSS(3)";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running vBulletin, a web based bulletin board system 
written in PHP.

The remote version of this software seems to be prior or equal to version 2.3.5
or 3.0.5.
These versions are vulnerable to a cross-site scripting issue, due to a 
failure of the application to properly sanitize user-supplied URI input.

As a result of this vulnerability, it is possible for a remote attacker
to create a malicious link containing script code that will be executed 
in the browser of an unsuspecting user when followed. 

This may facilitate the theft of cookie-based authentication credentials 
as well as other attacks.

Solution : Upgrade to versoin 2.3.6 or 3.0.6
Risk factor : Medium";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks BBTag XSS flaw in vBulletin";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 David Maciejak");
 family["english"] = "CGI abuses : XSS";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl", "vbulletin_detect.nasl");
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
  if (ver =~ '([0-1]\\.|2\\.([0-2])?[^0-9]|2\\.3(\\.[0-5])?[^0-9]|3\\.0(\\.[0-5])?[^0-9])' ) security_warning(port);
}
