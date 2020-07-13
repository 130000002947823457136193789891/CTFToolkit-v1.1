#
# (C) Tenable Network Security
#
#

if(description)
{
  script_id(12025);
  script_bugtraq_id(9445);
  if ( defined_func("script_xref") ) {
    script_xref(name:"OSVDB", value:"3616");
  }
  script_version("$Revision: 1.4 $");
  name["english"] = "Mambo Code injection Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
There is a flaw in the installed version of Mambo Open Source that may
allow an attacker to execute arbitrary remote PHP code on this host. 

Solution : Upgrade to the latest version of this software.
Risk factor : High";
  script_description(english:desc["english"]);
 
  summary["english"] = "Detect mambo code injection vuln";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2004-2005 Tenable Network Security");

  family["english"] = "CGI abuses";
  script_family(english:family["english"]);
  script_dependencie("mambo_detect.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if (! get_port_state(port) ) exit(0);
if (! can_host_php(port:port) ) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/mambo_mos"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
 dir = matches[2];

 req = http_get(item:string(dir, "/modules/mod_mainmenu.php?mosConfig_absolute_path=http://xxxxxxx"), port:port);
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
 if ( res == NULL ) exit(0);

 if ("http://xxxxxxx/modules" >< res ) security_hole(port);
}
