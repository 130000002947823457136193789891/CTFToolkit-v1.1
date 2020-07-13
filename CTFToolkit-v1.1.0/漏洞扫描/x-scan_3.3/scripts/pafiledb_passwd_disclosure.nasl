#
# (C) Tenable Network Security
# This script is written by Shruti@tenablesecurity.com
#

if (description)
{
 script_id(15911);
 script_cve_id("CAN-2004-1219");
 script_bugtraq_id(11818);
 script_version ("$Revision: 1.2 $");

 script_name(english:"paFileDB password hash disclosure");
 desc["english"] = "
The remote host is using paFileDB which is a PHP based 
database of files.

According to its version number, the remote version of this software
is vulnerable to an attack that would allow users to view the 
password hash of user accounts, including administrator account.

The vulnerability exists when session based authentication is performed.

This vulnerability is reported to be present in version 3.1 or lower.
This may allow an attacker to perform brute force attack on the password
hash and gain access to account information.

Solution: Upgrade to version 3.2 of paFileDB when available
Risk factor : High";

 script_description(english:desc["english"]);
 script_summary(english:"Determines the version of paFileDB");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses", francais:"Abus de CGI");
 script_copyright(english:"This script is Copyright (C) 2004-2005 Tenable Network Security");
 script_dependencie("pafiledb_detect.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/pafiledb"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
 ver = matches[1];
 if (ver =~ "^([0-2]|3\.0|3\.1( *b|$))") security_warning(port);
}
