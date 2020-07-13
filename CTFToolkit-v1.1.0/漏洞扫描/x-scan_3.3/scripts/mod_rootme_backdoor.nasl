#
# This script was written by Noam Rathaus and upgraded by Alexei Chicheev for mod_rootme v.0.3 detection 
#
# GPLv2
#

if(description)
{
  script_id(13644);
  script_version("$Revision: 1.6 $");
  script_cve_id("CAN-1999-0660");
  name["english"] = "Apache mod_rootme Backdoor";
  script_name(english:name["english"]);
 
  desc["english"] = "
The remote system appears to be running the mod_rootme module,
this module silently allows a user to gain a root shell access
to the machine via HTTP requests.

Solution:
- Remove the mod_rootme module from httpd.conf/modules.conf
- Consider reinstalling the computer, as it is likely to have been 
compromised by an intruder 

Risk factor : High";

  script_description(english:desc["english"]);
 
  summary["english"] = "Detect mod_rootme Backdoor";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2004 Noam Rathaus and upgraded (15.03.2005) by Alexei Chicheev for mod_rootme v.0.3 detection ");

  family["english"] = "Backdoors";
  script_family(english:family["english"]);
  script_dependencie("http_version.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

port = get_http_port(default:80);
if (! port) exit(0);

if ( report_paranoia < 2 )
{
 banner = get_http_banner(port:port);
 if ( ! banner || "Apache" >!< banner ) exit(0);
}

if(!get_port_state(port))exit(0);
soc = open_sock_tcp(port);
if (soc)
{
 # Syntax for this Trojan is essential... normal requests won't work...
 # We need to emulate a netcat, slow sending, single line each time, unlike HTTP that can
 # receive everything as a block
 send(socket:soc, data:string("GET root HTTP/1.0\n"));
 sleep(1);
 send(socket:soc, data:string("\n"));
 sleep(1);
 res_vx = recv(socket:soc, length:1024);
 if ( ! res_vx ) exit(0);
 send(socket:soc, data:string("id\n"));
 res = recv(socket:soc, length:1024);
 if (res == NULL) exit(0);
 if (ereg(pattern:"^uid=[0-9]+\(root\)", string:res) && ereg(pattern:"^rootme-[0-9].[0-9] ready", string:res_vx))
 {
  send(socket:soc, data:string("exit\n")); # If we don't exit we can cause Apache to crash
  security_hole(port:port);
 }
 close(soc);
}

