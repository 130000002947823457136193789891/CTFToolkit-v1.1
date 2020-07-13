#
# (C) Tenable Network Security
#
if(description)
{
 script_id(15948);
 script_bugtraq_id(11886); 
 script_cve_id("CAN-2004-1147", "CAN-2004-1148");
 script_version("$Revision: 1.3 $");
 name["english"] = "phpMyAdmin Multiple Remote Vulnerabilities";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running phpMyAdmin, an open-source software
written in PHP to handle the administration of MySQL over the Web.

The remote version of this software is vulnerable to one (or both)
of the following flaws :

- An attacker may be able to exploit this software to execute arbitrary
commands on the remote host on a server which does not run PHP in safe mode.

- An attacker may be able to read arbitrary files on the remote host
through the argument 'sql_localfile' of the file 'read_dump.php'.

Solution : Upgrade to version 2.6.1-rc1 or newer
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks the version of phpMyAdmin";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 - 2005 Tenable Network Security");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("phpMyAdmin_detect.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Check starts here

include("http_func.inc");

port = get_http_port(default:80);
kb   = get_kb_item("www/" + port + "/phpMyAdmin");
if ( ! kb ) exit(0);
matches = eregmatch(pattern:"(.*) under (.*)", string:kb);
# Only 2.4.0 to 2.6.0plX affected
if ( ereg(pattern:"^(2\.[45]\..*|2\.6\.0|2\.6\.0-pl)", string:matches[1]))
	security_hole(port);
