#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# Ref: albanian haxorz
# This script is released under the GNU GPL v2

if(description)
{
  script_id(17199);
  script_bugtraq_id(12596);
  script_version("$Revision: 1.1 $");
  
  script_name(english:"ZeroBoard XSS");

 desc["english"] = "
The remote web server is hosting ZeroBoard, a web-based BBS application.

The remote version of this software is vulnerable to cross-site scripting 
and remote script injection due to a lack of sanitization of user-supplied 
data.

Successful exploitation of this issue may allow an attacker to execute 
malicious script code on a vulnerable server. 

Solution: Upgrade to the latest version
Risk factor : Medium";

  script_description(english:desc["english"]);
  script_summary(english:"Checks ZeroBoard XSS");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005 David Maciejak");
  script_family(english:"CGI abuses");
  script_require_ports("Services/www", 80);
  script_dependencie("http_version.nasl", "cross_site_scripting.nasl");
  exit(0);
}

#the code

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! get_port_state(port))exit(0);
if ( ! can_host_php(port:port) ) exit(0);

if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);


function check(loc)
{
  buf = http_get(item:string(loc,"/zboard.php?id=gallery&sn1=ALBANIAN%20RULEZ='%3E%3Cscript%3Efoo%3C/script%3E"), port:port);
  r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);

  if( r == NULL )exit(0);

  if("<script>foo</script>" >< r )
  {
    security_warning(port);
    exit(0);
  }
}

foreach dir (make_list("/bbs",cgi_dirs()))
{
 check(loc:dir);
}
