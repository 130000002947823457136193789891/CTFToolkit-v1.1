#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  This script is released under the GNU GPLv2
#

if(description)
{
  script_id(15936);
  script_version("$Revision: 1.4 $");
  script_name(english:"PunBB detection");

  desc["english"] = "
This script detects whether the remote host is running PunBB and
extracts the version number and location if found.
	
Risk factor : None";

  script_description(english:desc["english"]);

  script_summary(english:"Checks for presence of PunBB");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");

  script_family(english:"CGI abuses");

  script_dependencie("find_service.nes", "http_version.nasl");
  script_require_ports("Services/www");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (http_is_dead(port:port)) exit(0);
if (!can_host_php(port:port)) exit(0);

foreach dir (make_list(cgi_dirs(), "")) {
  req = http_get(item:string(dir, "/index.php"), port:port);
  r = http_keepalive_send_recv(port:port, data:req);
  if ( r == NULL ) exit(0);

  pat = "Powered by .*http://www\.punbb\.org/.>PunBB";
  if ( egrep(pattern:pat, string:r) ) {
    if ( ! dir ) dir = "/";
    version=eregmatch(pattern:string(".*", pat, "</a><br>.+Version: (.+)<br>.*"),string:r);
    # nb: starting with 1.2, version display is optional and off by default
    #     but it's still useful to know that it's installed.
    if ( version == NULL ) {
      version = "unknown";
      report = string("An unknown version of PunBB is installed under ", dir, " on the remote host.");
    }
    else {
      version = version[1];
      report = string("PunBB version ", version, " is installed under ", dir, " on the remote host.");
    }
    report = report + "

PunBB is a fast and lightweight PHP-powered discussion board. See
http://www.punbb.org/ for more information.

Risk factor : None";

    security_note(port:port, data:report);
    set_kb_item(name:"www/" + port + "/punBB", value:version + " under " + dir);
    exit(0);
  }
}
