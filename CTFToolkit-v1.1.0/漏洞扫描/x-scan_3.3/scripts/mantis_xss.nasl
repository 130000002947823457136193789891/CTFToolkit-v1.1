#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
#  (C) Tenable Netwok Security
#
#  Ref: Paul Richards
#
# This script is released under the GNU GPLv2

if(description)
{
 script_id(14344);
 script_bugtraq_id(9184);
 script_version ("$Revision: 1.4 $");

 name["english"] = "Mantis multiple unspecified XSS";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running the Mantis bug tracker.

The remote version of this software contains a flaw in the handling of some types 
of input by Mantis. Because of this, an attacker may be able to execute code 
in the security context of the site hosting the vulnerable software.


Solution : Upgrade to Mantis 0.18.1 or newer 
Risk factor : Medium"; 




 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the version of Mantis";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak",
		francais:"Ce script est Copyright (C) 2003 David Maciejak");
 family["english"] = "CGI abuses : XSS";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("mantis_detect.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);

vers = get_kb_item(string("www/", port, "/mantis/version"));
if(!vers)exit(0);
if(ereg(pattern:"0\.([0-9]\.|1[0-7]\.|18\.0[^0-9])", string:vers))
	security_warning(port);
	
