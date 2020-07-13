#
# (C) Tenable Network Security
#
# 

if (description) {
  script_id(17309);
  script_version("$Revision: 1.2 $");

  script_cve_id("CAN-2005-0735");
  script_bugtraq_id(12761);

  name["english"] = "NewsScript Access Validation Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
The remote host is running a version of NewsScript.co.uk's NewsScript
that allows a remote attacker to bypass authentication simply by
setting the 'mode' parameter to 'admin', thereby allowing him to add,
delete, or modify news stories and headlines at will. 

Solution : Upgrade to the latest version of NewsScript.
Risk factor : High";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for access validation vulnerability in NewsScript";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  family["english"] = "CGI abuses";
  script_family(english:family["english"]);

  script_dependencie("http_version.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);


# Search for NewsScript in a couple of different locations in addition to 
# cgi_dirs() based on googling for 'inurl:newsscript.pl'.
dirs = make_list(cgi_dirs());
xtra_dirs = make_array(
  "/news", 1
);
foreach dir (dirs) {
  # Set value to zero if it's already in dirs.
  if (!isnull(xtra_dirs[dir])) xtra_dirs[dir] = 0;
}
foreach dir (keys(xtra_dirs)) {
  # Add it to dirs if the value is still set.
  if (xtra_dirs[dir]) dirs = make_list(dirs, dir);
}

foreach dir (dirs) {
  # Let's try the exploit.
  req = http_get(item:string(dir, "/newsscript.pl?mode=admin"), port:port);
  res = http_keepalive_send_recv(port:port, data:req);

  # If the results have a link to add a record, there's a problem.
  if (egrep(string:res, pattern:"<a href=[^>]+/newsscript.pl\\?mode=admin&action=add")) 
    security_hole(port);
}
