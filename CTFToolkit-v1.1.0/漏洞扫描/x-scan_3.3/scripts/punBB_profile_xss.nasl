#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  This script is released under the GNU GPLv2
#

if(description)
{
 script_id(15940);
 script_bugtraq_id(11847);
 if (defined_func("script_xref")) script_xref(name:"OSVDB", value:"7975");

 name["english"] = "PunBB profile.php XSS";

 script_name(english:name["english"]);
 script_version ("$Revision: 1.3 $"); 
 desc["english"] = "
The remote host seems to be running PunBB, an open source fast 
and lightweight PHP powered discussion board.

This version is vulnerable to cross-site scripting flaws
threw 'profile.php' script.

With a specially crafted URL, an attacker can cause arbitrary
code execution resulting in a loss of integrity.

Solution : Update a least to version 1.1.4

See also: http://www.punbb.org/

Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for PunBB profile.php XSS";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 
 family["english"] = "CGI abuses : XSS";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("punBB_detect.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_http_port(default:80);

version = get_kb_item("www/" + port + "/punBB");
if ( ! version ) exit(0);

matches = eregmatch(pattern:"(.*) under (.*)", string:version);

if (egrep(pattern: "^(0\.|1\.0|1\.1[^.]|1\.1\.[0123]([^0-9]|$))",string: matches[1]))
{
    security_warning(port);
    exit(0);
}
