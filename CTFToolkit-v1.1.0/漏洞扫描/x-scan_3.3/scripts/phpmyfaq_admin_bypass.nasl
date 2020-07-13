#
# (C) Tenable Network Security
#


if(description)
{
 script_id(14188);
 script_bugtraq_id(10813);
 script_version("$Revision: 1.3 $");

 name["english"] = "phpMyFAQ Image Upload Authentication Bypass";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running phpMyFAQ - a set of PHP scripts to manage 
a Frequently Asked Questions (FAQ) list.

There is a flaw in the remote version of this software which may allow
an attacker to upload and delete arbitrary images on the remote host.

An attacker may exploit this problem to deface the remote web site.

Solution : Upgrade to phpMyFAQ 1.4.0a or newer
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check the version of phpMyFAQ";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2005 Tenable Network Security");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("phpmyfaq_detect.nasl");
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
install = get_kb_item(string("www/", port, "/phpmyfaq"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];
  if (ver =~ "(0\.|1\.([0-3]\.|4\.0[^a]))") security_hole(port);
}
