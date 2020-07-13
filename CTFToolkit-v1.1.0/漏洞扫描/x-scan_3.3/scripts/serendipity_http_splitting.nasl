#
# This script is (C) Tenable Network Security
#
#

if(description)
{
 script_id(15543);
 script_cve_id("CAN-2004-1620");
 script_bugtraq_id(11497);
 if (defined_func("script_xref")) {
  script_xref(name:"OSVDB", value:"11013");
  script_xref(name:"OSVDB", value:"11038");
  script_xref(name:"OSVDB", value:"11039");
 }
 script_version ("$Revision: 1.3 $");

 name["english"] = "Serendipity HTTP Response Splitting Vulnerability";

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote version of Serendipity is vulnerable to an HTTP
response-splitting vulnerability that may allow an attacker to perform a
cross-site scripting attack against the remote host. 

Solution : Upgrade to Serendipity 0.7.0rc1 or newer.
Risk factor : Medium";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of Serendipity";
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2004-2005 Tenable Network Security",
		francais:"Ce script est Copyright (C) 2004-2005 Tenable Network Security");
 family["english"] = "CGI abuses : XSS";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("serendipity_detect.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#


include("http_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/serendipity"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];
  if (ver =~ "0\.([0-6][^0-9]|7-b)") security_warning(port);
}
