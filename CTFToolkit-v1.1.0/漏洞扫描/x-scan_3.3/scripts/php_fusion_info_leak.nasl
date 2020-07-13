#
# (C) Tenable Network Security
#

if(description)
{
 script_id(16336);
 script_bugtraq_id(12482);
 script_version("$Revision: 1.1 $");
 
 name["english"] = "PHP-Fusion Viewthread.php Information Disclosure Vulnerability";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is using PHP-Fusion, a content management system, 
written in PHP which uses MySQL.

A vulnerability exists in the remote version of this software
which may allow an attacker to read the content of arbitrary
forums and threads, regardless of his privileges.

Solution : Upgrade to PHP-Fusion 5.00 or newer
Risk factor : Low";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the version of the remote PHP-Fusion";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("php_fusion_detect.nasl");
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

kb = get_kb_item("www/" + port + "/php-fusion");
if ( ! kb ) exit(0);

items = eregmatch(pattern:"(.*) under (.*)", string:kb);
version = items[1];

if ( ereg(pattern:"^([0-4]\.)", string:version) )
	security_warning(port);
