#
# (C) Tenable Network Security
# 



if(description)
{
  script_id(18039);
  script_version ("$Revision: 1.6 $");
  script_name(english:"Hydrogen Detection");
 
  desc["english"] = "
The remote host seems to be running Hydrogen, a backdoor used by penetration
testers to gather screen shots, download files or gain control of the
remote host.

Make sure that the use of this software on the remote host is authorized
by your security policy.

See also : http://www.immunitysec.com/products-hydrogen.shtml
Risk factor : Medium";

  script_description(english:desc["english"]);
 
  summary["english"] = "Detect Hydrogen";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
  script_family(english:"Service detection");
  script_dependencie("find_service2.nasl");
  script_require_ports("Services/unknown");
  script_require_keys("Settings/ThoroughTests");



  exit(0);
}

#
include ("misc_func.inc");
include ('global_settings.inc');

if ( ! thorough_tests ) exit(0);

port = get_kb_item("Services/unknown");
if (! port) exit(0);
if ( known_service(port:port) ) exit(0);
if (! get_port_state(port)) exit(0);

init_match = raw_string(1);
body_match = raw_string(0,0,1,0x10,0,0,0,0x1E,0,0,0,0,0,0);
req = raw_string(0);
soc = open_sock_tcp(port);
r = recv(socket:soc, length:1024);
if (r && r == init_match)
 {
       send(socket:soc, data:req);
       r = recv(socket:soc, length:14);
       if (r == body_match) {
	security_warning(port);
        close (soc);
	exit(0);
	}
 }

close (soc);
