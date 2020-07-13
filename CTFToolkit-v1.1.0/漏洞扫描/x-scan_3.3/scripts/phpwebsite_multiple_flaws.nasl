#
# (C) Tenable Network Security
#
# 

if(description)
{
 script_id(11816);

 
 script_version("$Revision: 1.6 $");
 name["english"] = "phpWebSite multiple flaws";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running phpWebSite

There are multiple flaws in the remote version of phpWebSite 
which may allow an attacker to gain the control of the remote
database, or to disable this site entirely.

Solution : Upgrade to the latest version of this software
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "SQL Injection and more.";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 - 2005 Tenable Network Security");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "http_version.nasl", "phpwebsite_detect.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Check starts here
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);


# Check each installed instance, stopping if we find a vulnerability.
installs = get_kb_list(string("www/", port, "/phpwebsite"));
if (isnull(installs)) exit(0);
foreach install (installs) {
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches)) {
    ver = matches[1];
    dir = matches[2];

    req = http_get(item:dir + "/index.php?module=calendar&calendar[view]=day&year=2003%00-1&month=", port:port);
    buf = http_keepalive_send_recv(port:port, data:req);
    if(buf == NULL)exit(0);

    if(egrep(pattern:".*select.*mod_calendar_events.*", string:buf)) {
      security_hole(port);
      exit(0);
    }
  }
}
