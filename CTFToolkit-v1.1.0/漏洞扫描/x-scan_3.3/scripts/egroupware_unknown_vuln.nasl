#
# (C) Tenable Network Security
#

if(description)
{
 script_id(15719);
 script_cve_id("CAN-2005-1129");
 script_bugtraq_id(11625, 13137, 13212);
 if (defined_func("script_xref")) {
  script_xref(name:"OSVDB", value:"15499");
 }
 script_version("$Revision: 1.4 $");
 
 name["english"] = "EGroupWare Multiple Vulnerabilitie";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running eGroupWare, a web-based groupware solution. 

It is reported that versions prior 1.0.0.006 are prone to an unspecified 
vulnerability in the JiNN application, an information disclosure
flaw in the email client application, and multiple as-yet unspecified
vulnerabilities.

Solution : Upgrade to eGroupWare 1.0.0.007 or later.
Risk factor: High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the version of EGroupWare";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2005 Tenable Network Security");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("egroupware_detect.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#


include("http_func.inc");

port = get_http_port(default:80);
kb   = get_kb_item("www/" + port + "/egroupware");
if ( ! kb ) exit(0);

stuff = eregmatch( pattern:"(.*) under (.*)", string:kb );
version = stuff[1];
 if(ereg(pattern:"^(0\.|1\.0\.0(\.00[0-6]|[^0-9\.]))", string:version) )
{
 	security_hole(port);
	exit(0);
}

