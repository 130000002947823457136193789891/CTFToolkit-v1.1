#
# (C) Tenable Network Security
#
#


if (description) {
  script_id(18621);
  script_version("$Revision: 1.1 $");

  script_bugtraq_id(14133);

  name["english"] = "PHPNews prevnext Parameter SQL Injection Vulnerability";
  script_name(english:name["english"]);

  desc["english"] = "
The remote host is running PHPNews, an open-source news application
written in PHP. 

The installed version of PHPNews is prone to a SQL injection attack
due to its failure to sanitize user-supplied input via the 'prevnext'
parameter of the 'news.php' script.  An attacker can exploit this flaw
to affect database queries, possibly revealing sensitive information,
launching attacks against the underlying database, and the like. 

Solution : Upgrade to PHPNews 1.2.6 or later.
Risk factor : Medium";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for prevnext parameter SQL injection vulnerability in PHPNews";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security.");

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
  # Try to exploit the flaw.
  req = http_get(
    item:string(
      dir, "/news.php?",
      "prevnext=1'", SCRIPT_NAME
    ),
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if it looks like a MySQL error.
  if ("mysql_fetch_assoc(): supplied argument is not a valid MySQL result" >< res){
    security_warning(port);
    exit(0);
  }
}
