#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
#  Ref: Cedric Cochin
#
#  This script is released under the GNU GPL v2

if(description)
{
 script_id(15770);
 script_bugtraq_id(11707); 
 script_version("$Revision: 1.4 $");
 name["english"] = "phpMyAdmin XSS";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running phpMyAdmin, an open-source software
written in PHP to handle the administration of MySQL over the Web.

This version is vulnerable to cross-site scripting attacks threw
read_dump.php script.

With a specially crafted URL, an attacker can cause arbitrary
code execution resulting in a loss of integrity.

Solution : Upgrade to version 2.6.0-pl3 or newer
Risk factor : Medium";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the version of phpMyAdmin";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 family["english"] = "CGI abuses : XSS";
 script_family(english:family["english"]);
 script_dependencie("phpMyAdmin_detect.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Check starts here
include("http_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if (!can_host_php(port:port) ) exit(0);


# Check each installed instance, stopping if we find a vulnerability.
installs = get_kb_list(string("www/", port, "/phpMyAdmin"));
if (isnull(installs)) exit(0);
foreach install (installs) {
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches)) {
    ver = matches[1];
    dir = matches[2];

  if ( ereg(pattern:"^(2\.[0-5]\..*|2\.6\.0|2\.6\.0-pl[12])", string:ver))
    security_warning(port);
  }
}
