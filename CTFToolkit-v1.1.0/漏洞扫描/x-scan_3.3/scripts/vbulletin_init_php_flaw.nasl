#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
#  Ref: vBulletin team
#
#  This script is released under the GNU GPL v2
#

if(description)
{
 script_id(16203);
 script_bugtraq_id(12299);
 script_version("$Revision: 1.2 $");
 
 name["english"] = "vBulletin Init.PHP unspecified vulnerability";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running vBulletin, a web based bulletin board system written
in PHP.

The remote version of this software is vulnerable to an unspecified issue. It is 
reported that versions 3.0.0 through to 3.0.4 are prone to a security flaw 
in 'includes/init.php'. Successful exploitation requires that 'register_globals' 
is enabled.

*** As Nessus solely relied on the banner of the remote host
*** this might be a false positive

See also : http://secunia.com/advisories/13901/
Solution : Upgrade to vBulletin 3.0.5 or newer
Risk factor : Medium";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the version of vBulletin";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 David Maciejak");
 family["english"] = "CGI abuses";
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
  if ( ver =~ '3.0(\\.[0-4])?[^0-9]' ) security_warning(port);
}
