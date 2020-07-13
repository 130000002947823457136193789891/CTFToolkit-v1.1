#
# (C) Tenable Network Security
#


if (description) {
  script_id(17240);
  script_version("$Revision: 1.2 $");

  script_cve_id(
    "CAN-2005-0615",
    "CAN-2005-0616",
    "CAN-2005-0617"
  );
  script_bugtraq_id(12683, 12684, 12685);

  script_name(english:"Multiple Vulnerabilities in PostNuke 0.760 RC2 and older");
  desc["english"] = "
The remote host is running PostNuke version 0.760 RC2 or older.  These
versions suffer from several vulnerabilities, among them :

  o SQL injection vulnerability in the News, NS-Polls and 
    NS-AddStory modules.
  o SQL injection vulnerability in the Downloads module.
  o Cross-site scripting vulnerabilities in the Downloads
    module.
  o Possible path disclosure vulnerability in the News module.

An attacker may use the SQL injection vulnerabilities to obtain the
password hash for the administrator or to corrupt the database
database used by PostNuke. 

Exploiting the XSS flaws may enable an attacker to inject arbitrary
script code into the browser of site administrators leading to 
disclosure of session cookies. 

See also : http://news.postnuke.com/Article2669.html

Solution : Either upgrade and apply patches for 0.750 or upgrade to
0.760 RC3 or later. 

Risk factor : High";
  script_description(english:desc["english"]);

  script_summary(english:"Detects multiple vulnerabilities in PostNuke 0.760 RC2 and older");

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses", francais:"Abus de CGI");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencie("postnuke_detect.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port))exit(0);
if (!can_host_php(port:port))exit(0);


kb = get_kb_item("www/" + port + "/postnuke" );
if (! kb) exit(0);
install = eregmatch(pattern:"(.*) under (.*)", string:kb );
ver = install[1];
dir = install[2];


# Try the SQL injection exploits.
exploits = make_list(
  "/index.php?catid='cXIb8O3",
  "/index.php?name=Downloads&req=search&query=&show=cXIb8O3",
  "/index.php?name=Downloads&req=search&query=&orderby="
);
foreach exploit (exploits) {
  req = http_get(item:string(dir, exploit), port:port);
  res = http_keepalive_send_recv(port:port, data:req);
  if (res == NULL) exit(0);

  # See any errors?
  if (res =~ "(DB Error: getArticles:|Fatal error: .+/modules/Downloads/dl-search.php)") {
    security_hole(port);
    exit(0);
  }
}

