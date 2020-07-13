#
# (C) Tenable Network Security
#
# 

if (description) {
  script_id(18494);
  script_version("$Revision: 1.2 $");
  script_bugtraq_id(13964);

  name["english"] = "ViRobot Linux Server Remote Buffer Overflow Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
The remote host is running ViRobot Linux Server, a commercial
anti-virus product for Linux. 

The installed version of ViRobot Linux Server suffers from a remote
buffer overflow vulnerability in its web-based management interface. 
By passing specially-crafted data through the 'ViRobot_ID' and
'ViRobot_PASS' cookies when calling the 'addschup' CGI script, an
attacker may be able to write arbitrary data to root's crontab entry,
thus giving him complete control over the affected host. 

See also : http://www.digitalmunition.com/DMA%5B2005-0614a%5D.txt
Solution : Unknown at this time.
Risk factor : High";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for remote buffer overflow vulnerability in ViRobot Linux Server";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencie("http_version.nasl");
  script_require_ports("Services/www", 8080);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:8080);
if (!get_port_state(port)) exit(1);


# For each CGI directory...
foreach dir (cgi_dirs()) {
  # Make sure the affected script exists.
  req = http_get(item:string(dir, "/addschup"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(1);

  # If it looks like the script.
  if ("<font size=2>You need to authenticate.</font>" >< res) {
    # Get the site's index.html -- it has the version number in its title.
    req = http_get(item:"/index.html", port:port);
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(1);

    # There's a problem if the version number is <= 2.0.
    if (
      egrep(
        string:res, 
        pattern:"<title>ViRobot Linux Server Ver ([01]\..*|2\.0)</title>"
      )
    ) {
      security_hole(port);
      exit(0);
    }
  }
}
