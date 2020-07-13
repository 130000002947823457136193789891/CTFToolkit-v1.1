#
# This script was written by Noam Rathaus
#
# GPLv2
#
# From: Guy Pearce <dt_student@hotmail.com>
# Date: 21.6.2004 08:01
# Subject: Multiple osTicket exploits!

# This script detects those osTicket systems that were backdoored,
# not the vulnerability

if(description)
{
  script_id(12649);
  script_version("$Revision: 1.3 $");
  name["english"] = "osTicket Backdoored";
  script_name(english:name["english"]);
 
  desc["english"] = "
There is a vulnerability in the current version of osTicket
that allows an attacker to upload an PHP script, and then access it
causing it to execute.
This attack is being actively exploited by attackers to take over
servers. This script tries to detect infected servers.

Solution:
1) Remove any PHP files from the /attachments/ directory.
2) Place an index.html file there to prevent directory listing of that
directory.
3) Upgrade osTicket to the latest version.

Risk factor : High";

  script_description(english:desc["english"]);
 
  summary["english"] = "Detect osTicker Backdoored";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2004 Noam Rathaus");

  family["english"] = "General";
  script_family(english:family["english"]);
  script_dependencie("http_version.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! port ) exit(0);
if ( ! can_host_php(port:port) ) exit(0);

if ( ! get_kb_item("www/" + port + "/osticket" )  ) exit(0);

function check_dir(path)
{
 req = http_get(item:path +  "/attachments/", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) return(0);
 if ("[DIR]" >< res)
 {
  # There is a directory there, so directory listing worked
  v = eregmatch(pattern: '<A HREF="([^"]+.php)">', string:res);
  if (isnull(v)) return;
  req = http_get(item:string(path, "/attachments/", v[1]), port:port);
  res = http_keepalive_send_recv(port:port, data:req);
  if ( res == NULL ) return(0);
  if ("PHP Shell" >< res ||
    "<input type = 'text' name = 'cmd' value = '' size = '75'>" >< res )
	{
	 security_hole(port: port);
  	 exit(0);
	}
 }
}

foreach dir ( cgi_dirs() ) check_dir(path:dir);

