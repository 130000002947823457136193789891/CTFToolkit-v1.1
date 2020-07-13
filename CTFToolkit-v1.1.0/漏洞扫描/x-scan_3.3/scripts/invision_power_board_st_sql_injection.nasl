#
# (C) Tenable Network Security
#
# 

if (description) {
  script_id(18011);
  script_version("$Revision: 1.2 $");

  script_cve_id("CAN-2005-1070");
  script_bugtraq_id(13097);

  name["english"] = "Invision Power Board st Parameter SQL Injection Vulnerability";
  script_name(english:name["english"]);
 
  desc["english"] = "
There is a version of Invision Power Board installed on the remote
host that suffers from an SQL injection vulnerability due to its
failure to sanitize user input via the 'st' parameter to the
'index.php' script.  An attacker can take advantage of this flaw to
inject arbitrary SQL statements into Invision Power Board, possibly
even modifying the database. 

Solution : Upgrade to Invision Power Board 2.0.0 or greater.
Risk factor : Medium";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for st parameter SQL injection vulnerability in Invision Power Board";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencie("invision_power_board_detect.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/invision_power_board"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Try to exploit it.
  req = http_get(
    item:string(
      dir, "/index.php?",
      "act=Members&", 
      "max_results=30&",
      "filter=1&",
      "sort_order=asc&",
      "sort_key=name&",
      # nb: the 'st' parameter is used in a SELECT statement as the offset in
      #     a LIMIT clause so appending a '--' will cause a syntax error
      #     since it tells MySQL to ignore the rest of the statement.
      "st=1--"
    ),
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  if ("<title>Invision Power Board Database Error" >< res) 
    security_warning(port);
}
